// Package app wires the sinkhole responder's runtime components together.
package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/admin"
	"github.com/huntastikus/sinkhole-responder/internal/config"
	"github.com/huntastikus/sinkhole-responder/internal/httpserver"
	"github.com/huntastikus/sinkhole-responder/internal/logbuf"
	"github.com/huntastikus/sinkhole-responder/internal/mgmt"
	"github.com/huntastikus/sinkhole-responder/internal/rulepacks"
	"github.com/huntastikus/sinkhole-responder/internal/rules"
	"github.com/huntastikus/sinkhole-responder/internal/state"
	"github.com/huntastikus/sinkhole-responder/internal/tlsx"
)

// Option configures Run.
type Option func(*runOptions)

type runOptions struct {
	readyFunc       func([]net.Addr)
	samplerInterval time.Duration
	history         *mgmt.History
	configPath      string
	logLevel        *slog.LevelVar
}

// WithReadyFunc registers a function called once all public listeners are
// bound. The supplied address slice is a snapshot and may be retained.
func WithReadyFunc(fn func(httpAddrs []net.Addr)) Option {
	return func(options *runOptions) {
		options.readyFunc = fn
	}
}

// WithSamplerInterval overrides the metrics history sampling interval.
// Non-positive values keep the default (1s). Primarily for tests and tuning.
func WithSamplerInterval(d time.Duration) Option {
	return func(options *runOptions) {
		options.samplerInterval = d
	}
}

// WithMetricsHistory injects the metrics history instance. When nil (default),
// Run creates its own only if the admin plane is enabled. Lets callers/tests
// observe the populated history.
func WithMetricsHistory(h *mgmt.History) Option {
	return func(options *runOptions) {
		options.history = h
	}
}

// WithConfigPath sets the on-disk config file path so the admin UI can save changes.
func WithConfigPath(path string) Option {
	return func(options *runOptions) {
		options.configPath = path
	}
}

// WithLogLevel supplies the process log-level control for live reloads.
func WithLogLevel(level *slog.LevelVar) Option {
	return func(options *runOptions) {
		options.logLevel = level
	}
}

type componentResult struct {
	name string
	err  error
}

func effectiveRules(cfg *config.Config) ([]rules.Rule, error) {
	return rulepacks.Merge(cfg.Rules, cfg.Rulepacks.Enabled)
}

// Run starts the responder and blocks until ctx is canceled or a component
// returns a fatal error. reloadCh delivers configuration paths to reload.
func Run(ctx context.Context, cfg *config.Config, version string, logger *slog.Logger, logRing *logbuf.Ring, reloadCh <-chan string, opts ...Option) error {
	if cfg == nil {
		return fmt.Errorf("configuration is nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	var options runOptions
	for _, option := range opts {
		if option != nil {
			option(&options)
		}
	}
	samplerInterval := options.samplerInterval
	if samplerInterval <= 0 {
		samplerInterval = time.Second
	}

	merged, err := effectiveRules(cfg)
	if err != nil {
		return fmt.Errorf("merge rulepacks: %w", err)
	}
	engine, err := rules.Compile(merged, cfg.ConfigDir)
	if err != nil {
		return fmt.Errorf("compile rules: %w", err)
	}

	metrics := mgmt.NewMetrics(version)
	resolvedStateDir := cfg.StateDir
	if resolvedStateDir == "" {
		resolvedStateDir = cfg.ConfigDir
	}
	var appState *state.Dir
	if cfg.TLS.Mode == "local-ca" || cfg.Admin.Enabled {
		appState, err = state.New(resolvedStateDir)
		if err != nil {
			return fmt.Errorf("initialize state directory %q: %w", resolvedStateDir, err)
		}
	}

	resolvedLocalCA := cfg.TLS.LocalCA
	needsAdminCA := cfg.Admin.Enabled && cfg.Admin.TLS.Enabled && cfg.Admin.TLS.CertFile == "" && cfg.Admin.TLS.KeyFile == ""
	if cfg.TLS.Mode == "local-ca" || needsAdminCA {
		caCertPath, caKeyPath := tlsx.ResolveCAPaths(cfg.TLS.LocalCA, resolvedStateDir)
		missing, err := caFileMissing(caCertPath, caKeyPath)
		if err != nil {
			return err
		}
		if missing {
			if _, _, err := tlsx.CreateCA(appState.Path("tls"), "Sinkhole Responder Local CA", 10); err != nil {
				return fmt.Errorf("generate local CA: %w", err)
			}
		}
		resolvedLocalCA.CACert = caCertPath
		resolvedLocalCA.CAKey = caKeyPath
	}

	var tlsConfig *tls.Config
	switch cfg.TLS.Mode {
	case "disabled":
		if len(cfg.Listen.HTTPS) != 0 {
			return fmt.Errorf("listen.https requires TLS mode static or local-ca")
		}
	case "static":
		tlsConfig, err = tlsx.StaticConfig(cfg.TLS.Static)
		if err != nil {
			return fmt.Errorf("configure static TLS: %w", err)
		}
	case "local-ca":
		tlsConfig, err = tlsx.LocalCAConfig(resolvedLocalCA, metrics, logger)
		if err != nil {
			return fmt.Errorf("configure local CA TLS: %w", err)
		}
		logger.Info("local-ca TLS mode configured")
	default:
		return fmt.Errorf("unsupported TLS mode %q", cfg.TLS.Mode)
	}

	server := httpserver.New(cfg, engine, logger, metrics)
	var currentConfig atomic.Pointer[config.Config]
	currentConfig.Store(cfg)
	// restartPending is derived (not latched) from the immutable startup baseline
	// on every reload, so reverting a restart-only change clears it.
	var restartPending atomic.Bool
	var applyMu sync.Mutex
	applyConfig := func(reloaded *config.Config) error {
		if reloaded == nil {
			return fmt.Errorf("configuration is nil")
		}

		applyMu.Lock()
		defer applyMu.Unlock()
		if err := reloaded.Validate(); err != nil {
			return fmt.Errorf("validate configuration: %w", err)
		}
		merged, err := effectiveRules(reloaded)
		if err != nil {
			return fmt.Errorf("merge rulepacks: %w", err)
		}
		reloadedEngine, err := rules.Compile(merged, reloaded.ConfigDir)
		if err != nil {
			return fmt.Errorf("compile rules: %w", err)
		}
		needsRestart := config.RestartRequired(cfg, reloaded)
		restartPending.Store(needsRestart)
		if needsRestart {
			logger.Warn("configuration change requires a restart to take effect; live changes applied")
		}
		current := currentConfig.Load()
		if options.logLevel != nil && current.Logging.Level != reloaded.Logging.Level {
			var level slog.Level
			if err := level.UnmarshalText([]byte(reloaded.Logging.Level)); err != nil {
				return fmt.Errorf("parse logging level: %w", err)
			}
			options.logLevel.Set(level)
		}
		server.SwapConfig(reloaded, reloadedEngine)
		currentConfig.Store(reloaded)
		logger.Info("configuration reloaded", "rule_count", reloadedEngine.Len())
		return nil
	}

	var adminServer *admin.Server
	var history *mgmt.History
	if cfg.Admin.Enabled {
		history = options.history
		if history == nil {
			history = mgmt.NewHistory()
		}
		_, credentialPresent, err := admin.LoadCredential(appState)
		if err != nil {
			return fmt.Errorf("load admin credential: %w", err)
		}
		if !credentialPresent && !loopbackOnlyListen(cfg.Admin.Listen) {
			logger.Warn("ADMIN PLANE EXPOSED WITHOUT A PASSWORD: reachable on the LAN until first-run setup completes",
				"admin_listen", cfg.Admin.Listen,
			)
		}
		adminServer, err = admin.New(admin.Deps{
			Cfg:            currentConfig.Load,
			ConfigPath:     options.configPath,
			Reload:         applyConfig,
			RestartPending: restartPending.Load,
			Metrics:        metrics,
			History:        history,
			State:          appState,
			LogBuf:         logRing,
			Logger:         logger,
		})
		if err != nil {
			return fmt.Errorf("initialize admin server: %w", err)
		}
	}

	httpsListeners, err := bindListeners("HTTPS", cfg.Listen.HTTPS)
	if err != nil {
		return err
	}

	logger.Info("sinkhole responder starting",
		"version", version,
		"http_listen", cfg.Listen.HTTP,
		"https_listen", cfg.Listen.HTTPS,
		"management_listen", cfg.Management.Listen,
		"tls_mode", cfg.TLS.Mode,
		"rule_count", engine.Len(),
	)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	componentCount := 1
	if len(cfg.Listen.HTTP) != 0 {
		componentCount++
	}
	if len(httpsListeners) != 0 {
		componentCount++
	}
	if adminServer != nil {
		componentCount++
		componentCount++
	}
	results := make(chan componentResult, componentCount)
	if len(cfg.Listen.HTTP) != 0 {
		go func() {
			results <- componentResult{name: "public HTTP server", err: server.Start(runCtx)}
		}()
	}
	if len(httpsListeners) != 0 {
		go func() {
			results <- componentResult{name: "public HTTPS server", err: server.StartTLSListeners(runCtx, httpsListeners, tlsConfig)}
		}()
	}
	go func() {
		results <- componentResult{name: "management server", err: mgmt.Serve(runCtx, cfg, metrics, logger)}
	}()
	if adminServer != nil {
		go func() {
			results <- componentResult{name: "admin server", err: adminServer.Serve(runCtx)}
		}()
		go func() {
			mgmt.RunSampler(runCtx, metrics, history, samplerInterval)
			results <- componentResult{name: "metrics sampler"}
		}()
	}

	var reloads sync.WaitGroup
	reloads.Add(1)
	go func() {
		defer reloads.Done()
		reloadLoop(runCtx, logger, reloadCh, applyConfig)
	}()

	var readyTicker *time.Ticker
	var ready <-chan time.Time
	if options.readyFunc != nil {
		readyTicker = time.NewTicker(time.Millisecond)
		ready = readyTicker.C
		defer readyTicker.Stop()
	}

	remaining := componentCount
	wantReadyAddrs := len(cfg.Listen.HTTP) + len(cfg.Listen.HTTPS)
	var firstErr error
	parentDone := ctx.Done()
	for remaining > 0 {
		select {
		case <-parentDone:
			cancel()
			parentDone = nil
		case <-ready:
			addrs := server.Addrs()
			if len(addrs) == wantReadyAddrs {
				options.readyFunc(addrs)
				ready = nil
			}
		case result := <-results:
			remaining--
			if result.err != nil && firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", result.name, result.err)
				cancel()
				parentDone = nil
			}
		}
	}

	cancel()
	reloads.Wait()
	return firstErr
}

func caFileMissing(certPath, keyPath string) (bool, error) {
	missing := false
	for _, path := range []string{certPath, keyPath} {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			missing = true
		} else if err != nil {
			return false, fmt.Errorf("inspect local CA file %q: %w", path, err)
		}
	}
	return missing, nil
}

func reloadLoop(ctx context.Context, logger *slog.Logger, reloadCh <-chan string, apply func(*config.Config) error) {
	for {
		select {
		case <-ctx.Done():
			return
		case path, ok := <-reloadCh:
			if !ok {
				return
			}
			reloaded, err := config.Load(path)
			if err != nil {
				logger.Error("reload failed, keeping previous configuration", "error", err)
				continue
			}
			if err := apply(reloaded); err != nil {
				logger.Error("reload failed, keeping previous configuration", "error", err)
			}
		}
	}
}

func loopbackOnlyListen(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func bindListeners(kind string, addresses []string) ([]net.Listener, error) {
	listeners := make([]net.Listener, 0, len(addresses))
	for _, address := range addresses {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			for _, bound := range listeners {
				_ = bound.Close()
			}
			return nil, fmt.Errorf("bind %s listener %q: %w", kind, address, err)
		}
		listeners = append(listeners, listener)
	}
	return listeners, nil
}
