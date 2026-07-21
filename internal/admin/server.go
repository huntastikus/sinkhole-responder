package admin

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/config"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/logbuf"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/mgmt"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/state"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/tlsx"
	"golang.org/x/time/rate"
)

const (
	contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
	adminShutdownTimeout  = 5 * time.Second
	systemHealthBanner    = `<section id="system-health-banner" class="system-health-banner" role="status" aria-live="polite" aria-atomic="true" hidden>
    <div class="system-health-overall">
      <span id="system-health-dot" class="system-health-dot" aria-hidden="true"></span>
      <strong>System <span id="system-health-overall">checking</span></strong>
    </div>
    <ul id="system-health-checks" class="system-health-checks" aria-label="System health checks"></ul>
  </section>`
	systemHealthScript = `<script type="module" src="/assets/status.js"></script>`
)

//go:embed web
var embeddedWeb embed.FS

// Deps contains the current configuration and services used by the admin plane.
type Deps struct {
	Cfg            func() *config.Config
	ConfigPath     string
	Reload         func(*config.Config) error
	RestartPending func() bool
	Metrics        *mgmt.Metrics
	History        *mgmt.History
	State          *state.Dir
	LogBuf         *logbuf.Ring
	Logger         *slog.Logger
}

// Server owns the admin router, embedded assets, and listener lifecycle.
type Server struct {
	deps            Deps
	router          *http.ServeMux
	web             fs.FS
	logger          *slog.Logger
	displayVersion  string
	sessionKey      []byte
	credentialFound atomic.Bool
	loginLimitersMu sync.Mutex
	loginLimiters   map[string]*rate.Limiter
	setupMu         sync.Mutex
	configWriteMu   sync.Mutex
	// adminTLSActive records whether the admin plane is served over HTTPS as it
	// was bound at startup. Cookie Secure flags pin to this, not the live config,
	// so a restart-pending admin-TLS change never issues cookies mismatched to
	// the topology actually serving them.
	adminTLSActive    bool
	restartInProgress atomic.Bool
	// triggerRestart performs the actual process restart; overridable in tests.
	triggerRestart func()
	restartDelay   time.Duration
}

// New creates an admin server and registers its core routes.
func New(deps Deps) (*Server, error) {
	if deps.Cfg == nil {
		return nil, errors.New("admin configuration provider is nil")
	}
	if deps.Cfg() == nil {
		return nil, errors.New("admin configuration is nil")
	}

	web, err := fs.Sub(embeddedWeb, "web")
	if err != nil {
		return nil, fmt.Errorf("open embedded admin assets: %w", err)
	}
	var sessionKey []byte
	if deps.State != nil {
		sessionKey, err = LoadOrCreateSessionKey(deps.State)
		if err != nil {
			return nil, fmt.Errorf("load admin session key: %w", err)
		}
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	displayVersion := "dev"
	if deps.Metrics != nil {
		displayVersion = formatDisplayVersion(deps.Metrics.Snapshot().Version)
	}

	server := &Server{
		deps:           deps,
		router:         http.NewServeMux(),
		web:            web,
		logger:         logger,
		displayVersion: displayVersion,
		sessionKey:     sessionKey,
		loginLimiters:  make(map[string]*rate.Limiter),
		adminTLSActive: deps.Cfg().Admin.TLS.Enabled,
		restartDelay:   restartSignalDelay,
	}
	server.triggerRestart = server.signalSelfTerminate
	for route, name := range map[string]string{
		"/{$}":            "index.html",
		"/wizard":         "wizard.html",
		"/config":         "config.html",
		"/rules":          "rules.html",
		"/rulepacks":      "rulepacks.html",
		"/tools":          "tools.html",
		"/tools/detector": "detector.html",
		"/tls":            "tls.html",
		"/logs":           "logs.html",
		"/help/{$}":       "help/index.html",
	} {
		server.router.HandleFunc("GET "+route, server.page(name))
	}
	for _, topic := range helpTopicSlugs {
		server.router.HandleFunc("GET /help/"+topic, server.page("help/"+topic+".html"))
	}
	for _, platform := range []string{"windows", "macos", "ios", "android", "debian", "firefox", "chrome"} {
		server.router.HandleFunc("GET /help/trust-"+platform, server.page("help/trust-"+platform+".html"))
	}
	server.router.Handle("GET /assets/", assetsHandler(web))
	server.router.HandleFunc("GET /login", server.handleLoginPage)
	server.router.HandleFunc("POST /login", server.handleLogin)
	server.router.HandleFunc("POST /logout", server.handleLogout)
	server.router.HandleFunc("GET /setup", server.handleSetupPage)
	server.router.HandleFunc("POST /setup", server.handleSetup)
	server.router.HandleFunc("GET /api/stats", server.handleStats)
	server.router.HandleFunc("GET /api/stats/history", server.handleStatsHistory)
	server.router.HandleFunc("GET /api/system/health", server.handleSystemHealth)
	server.router.HandleFunc("POST /api/system/restart", server.handleRestart)
	server.router.HandleFunc("GET /api/system/lan-ip", server.handleLANIP)
	server.router.HandleFunc("GET /api/logs", server.handleLogs)
	server.router.HandleFunc("GET /api/config", server.handleConfig)
	server.router.HandleFunc("PUT /api/config", server.handleConfigWrite)
	server.router.HandleFunc("GET /api/config/raw", server.handleRawConfig)
	server.router.HandleFunc("PUT /api/config/raw", server.handleRawConfigWrite)
	server.router.HandleFunc("GET /api/config/export", server.handleConfigExport)
	server.router.HandleFunc("POST /api/config/import", server.handleConfigImport)
	server.router.HandleFunc("GET /api/rules", server.handleRules)
	server.router.HandleFunc("PUT /api/rules", server.handleRulesWrite)
	server.router.HandleFunc("POST /api/rules/reorder", server.handleRulesReorder)
	server.router.HandleFunc("POST /api/rules/preview", server.handleRulesPreview)
	server.router.HandleFunc("GET /api/assets", server.handleAssets)
	server.router.HandleFunc("GET /api/rulepacks", server.handleRulepacks)
	server.router.HandleFunc("POST /api/rulepacks/toggle", server.handleRulepackToggle)
	server.router.HandleFunc("POST /api/tools/test-domain", server.handleTestDomain)
	server.router.HandleFunc("GET /api/tools/agh-config", server.handleAGHConfig)
	server.router.HandleFunc("GET /api/tls", server.handleTLSStatus)
	server.router.HandleFunc("POST /api/ca/generate", server.handleGenerateCA)
	server.router.HandleFunc("POST /api/tls/upload", server.handleTLSUpload)
	server.router.HandleFunc("POST /api/tls/mode", server.handleTLSMode)
	server.router.HandleFunc("GET /api/ca/download", server.handleCADownload)
	return server, nil
}

// Handler returns the admin router wrapped in recovery, security, and cache middleware.
func (s *Server) Handler() http.Handler {
	return s.middleware(s.router)
}

// Serve runs the configured HTTP listener and optional HTTPS listener until ctx is canceled.
func (s *Server) Serve(ctx context.Context) error {
	cfg := s.deps.Cfg()
	adminConfig := cfg.Admin

	httpListener, err := net.Listen("tcp", adminConfig.Listen)
	if err != nil {
		return fmt.Errorf("bind admin HTTP listener: %w", err)
	}

	running := []runningServer{{
		name: "HTTP",
		server: &http.Server{
			Handler: s.httpHandler(adminConfig),
		},
		listener: httpListener,
	}}
	if adminConfig.TLS.Enabled {
		tlsConfig, err := s.resolveTLS(adminConfig)
		if err != nil {
			_ = httpListener.Close()
			return err
		}
		tcpListener, err := net.Listen("tcp", adminConfig.TLS.Listen)
		if err != nil {
			_ = httpListener.Close()
			return fmt.Errorf("bind admin HTTPS listener: %w", err)
		}
		running = append(running, runningServer{
			name: "HTTPS",
			server: &http.Server{
				Handler:   s.Handler(),
				TLSConfig: tlsConfig,
			},
			listener: tls.NewListener(tcpListener, tlsConfig),
		})
	}

	serveErrors := make(chan error, len(running))
	for _, item := range running {
		s.logger.Info("admin listener started", "scheme", strings.ToLower(item.name), "addr", item.listener.Addr().String())
		go func() {
			serveErrors <- item.server.Serve(item.listener)
		}()
	}

	select {
	case <-ctx.Done():
		if err := shutdownAdminServers(running); err != nil {
			return err
		}
		for range running {
			if err := <-serveErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("serve admin listener: %w", err)
			}
		}
		return nil
	case err := <-serveErrors:
		shutdownErr := shutdownAdminServers(running)
		for range len(running) - 1 {
			<-serveErrors
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve admin listener: %w", err)
		}
		return shutdownErr
	}
}

type runningServer struct {
	name     string
	server   *http.Server
	listener net.Listener
}

func (s *Server) page(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		s.serveWebPage(w, name)
	}
}

func assetsHandler(web fs.FS) http.Handler {
	files := http.StripPrefix("/assets/", http.FileServerFS(web))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, ".js") && !strings.HasSuffix(r.URL.Path, ".css") {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
}

func (s *Server) serveWebPage(w http.ResponseWriter, name string) {
	page, err := fs.ReadFile(s.web, name)
	if err != nil {
		s.logger.Error("read embedded admin page", "name", name, "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	footer := `<footer class="app-footer"><span>` + template.HTMLEscapeString(s.displayVersion) + `</span></footer>`
	html := strings.Replace(string(page), "<body>", "<body class=\"admin-body\">\n  "+systemHealthBanner, 1)
	html = strings.Replace(html, "</body>", "  "+footer+"\n  "+systemHealthScript+"\n</body>", 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return s.baseMiddleware(s.authGate(s.csrfGate(next)))
}

func (s *Server) baseMiddleware(next http.Handler) http.Handler {
	return s.securityHeaders(s.recoverPanic(s.cacheControl(next)))
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("recovered admin handler panic", "panic", recovered, "stack", string(debug.Stack()))
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) cacheControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) httpHandler(adminConfig config.AdminConfig) http.Handler {
	if adminConfig.TLS.Enabled && adminConfig.TLS.RedirectHTTP {
		return s.redirectHandler(adminConfig.TLS.Listen)
	}
	return s.Handler()
}

func (s *Server) redirectHandler(tlsListen string) http.Handler {
	return s.baseMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target, err := httpsRedirectURL(r, tlsListen)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	}))
}

func (s *Server) resolveTLS(adminConfig config.AdminConfig) (*tls.Config, error) {
	certPath := adminConfig.TLS.CertFile
	keyPath := adminConfig.TLS.KeyFile
	if (certPath == "") != (keyPath == "") {
		return nil, errors.New("admin TLS cert_file and key_file must be set together")
	}
	if certPath == "" {
		if s.deps.State == nil {
			return nil, errors.New("admin TLS state directory is unavailable")
		}
		cfg := s.deps.Cfg()
		certPath, keyPath = tlsx.ResolveCAPaths(cfg.TLS.LocalCA, s.deps.State.Root)
		tlsConfig, err := tlsx.AdminCAConfig(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("configure CA-signed admin TLS: %w", err)
		}
		return tlsConfig, nil
	}

	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load admin TLS keypair: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	}, nil
}

func httpsRedirectURL(r *http.Request, tlsListen string) (string, error) {
	_, tlsPort, err := net.SplitHostPort(tlsListen)
	if err != nil {
		return "", fmt.Errorf("parse admin TLS listen address: %w", err)
	}
	host := requestHostname(r.Host)
	if host == "" {
		host, _, err = net.SplitHostPort(tlsListen)
		if err != nil {
			return "", fmt.Errorf("parse admin TLS listen address: %w", err)
		}
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}

	destination := host
	if tlsPort != "443" {
		destination = net.JoinHostPort(host, tlsPort)
	}
	target := &url.URL{
		Scheme:   "https",
		Host:     destination,
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
	}
	return target.String(), nil
}

func requestHostname(hostPort string) string {
	if host, _, err := net.SplitHostPort(hostPort); err == nil {
		return host
	}
	return strings.Trim(hostPort, "[]")
}

func shutdownAdminServers(running []runningServer) error {
	shutdownContext, cancel := context.WithTimeout(context.Background(), adminShutdownTimeout)
	defer cancel()

	errorsByServer := make(chan error, len(running))
	var wait sync.WaitGroup
	for _, item := range running {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := item.server.Shutdown(shutdownContext); err != nil {
				_ = item.server.Close()
				errorsByServer <- fmt.Errorf("shutdown admin %s listener: %w", item.name, err)
			}
		}()
	}
	wait.Wait()
	close(errorsByServer)
	for err := range errorsByServer {
		return err
	}
	return nil
}
