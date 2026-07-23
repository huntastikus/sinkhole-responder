// Package httpserver serves public sinkhole responses.
package httpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/config"
	"github.com/huntastikus/sinkhole-responder/internal/mgmt"
	"github.com/huntastikus/sinkhole-responder/internal/respond"
	"github.com/huntastikus/sinkhole-responder/internal/rules"
	"golang.org/x/net/http2"
)

const shutdownTimeout = 10 * time.Second

type serverState struct {
	cfg *config.Config
	eng *rules.Engine
}

// Server owns the public HTTP handler and listeners.
type Server struct {
	state        atomic.Pointer[serverState]
	logger       *slog.Logger
	accessLogger *slog.Logger
	metrics      *mgmt.Metrics
	handler      http.Handler
	limiters     clientLimiters
	addrsMu      sync.RWMutex
	addrs        []net.Addr
}

// New builds the public HTTP server. Listener addresses, timeouts, and request
// size limits are fixed until the server is restarted; SwapConfig updates rate
// limits and the other request-time behavior.
func New(cfg *config.Config, eng *rules.Engine, logger *slog.Logger, m *mgmt.Metrics) *Server {
	if cfg == nil {
		cfg = &config.Config{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		logger:       logger,
		accessLogger: logger.With("logger", "access"),
		metrics:      m,
	}
	s.state.Store(&serverState{cfg: cfg, eng: eng})
	s.limiters.configure(cfg.Limits.RatePerIP, cfg.Limits.RateBurst)

	var handler http.Handler = http.HandlerFunc(s.respond)
	handler = bodyLimitMiddleware(cfg.Limits.MaxBodyBytes, handler)
	handler = methodMiddleware(handler)
	handler = rateLimitMiddleware(&s.limiters, handler)
	s.handler = recoverMiddleware(s, handler)

	m.SetRuleCount(eng.Len())
	return s
}

// Handler returns the complete middleware-wrapped public handler.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// Addrs returns the addresses published by Start and StartTLSListeners.
func (s *Server) Addrs() []net.Addr {
	s.addrsMu.RLock()
	defer s.addrsMu.RUnlock()

	return append([]net.Addr(nil), s.addrs...)
}

// SwapConfig atomically replaces the rules and live request configuration.
// Listen addresses, timeouts, and header/body limits require a restart.
func (s *Server) SwapConfig(cfg *config.Config, eng *rules.Engine) {
	if cfg == nil {
		cfg = &config.Config{}
	}
	s.limiters.updateLimits(cfg.Limits.RatePerIP, cfg.Limits.RateBurst)
	s.state.Store(&serverState{cfg: cfg, eng: eng})
	s.metrics.SetRuleCount(eng.Len())
}

// Start binds every configured plain-HTTP address and serves until ctx is
// canceled. Binding is all-or-nothing.
func (s *Server) Start(ctx context.Context) error {
	state := s.state.Load()
	if state == nil || len(state.cfg.Listen.HTTP) == 0 {
		return errors.New("no HTTP listeners configured")
	}

	listeners := make([]net.Listener, 0, len(state.cfg.Listen.HTTP))
	for _, address := range state.cfg.Listen.HTTP {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			for _, bound := range listeners {
				_ = bound.Close()
			}
			return fmt.Errorf("bind HTTP listener %q: %w", address, err)
		}
		listeners = append(listeners, listener)
	}

	s.publishAddrs(listeners)
	return s.startListeners(ctx, listeners, state.cfg.Limits, nil)
}

// StartTLSListeners publishes and serves caller-provided listeners with TLS and
// HTTP/2 enabled until ctx is canceled.
func (s *Server) StartTLSListeners(ctx context.Context, listeners []net.Listener, tlsConfig *tls.Config) error {
	state := s.state.Load()
	if state == nil {
		return errors.New("server has no configuration")
	}
	if tlsConfig == nil {
		return errors.New("TLS configuration is nil")
	}
	if err := validateListeners(listeners); err != nil {
		return err
	}
	s.publishAddrs(listeners)
	return s.startListeners(ctx, listeners, state.cfg.Limits, tlsConfig)
}

func (s *Server) startListeners(ctx context.Context, listeners []net.Listener, limits config.LimitsConfig, tlsConfig *tls.Config) error {
	// Preserve values from the caller while allowing Shutdown, rather than
	// parent cancellation, to control the graceful lifetime of active requests.
	baseCtx, cancelBase := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelBase()

	servers := make([]*http.Server, len(listeners))
	serveErrors := make(chan error, len(listeners))
	for i, listener := range listeners {
		server := &http.Server{
			Handler:        s.handler,
			ReadTimeout:    limits.ReadTimeout,
			WriteTimeout:   limits.WriteTimeout,
			IdleTimeout:    limits.IdleTimeout,
			MaxHeaderBytes: limits.MaxHeaderBytes,
			ErrorLog:       slog.NewLogLogger(s.logger.Handler(), slog.LevelDebug),
			BaseContext: func(net.Listener) context.Context {
				return baseCtx
			},
		}
		serveListener := listener
		if tlsConfig != nil {
			server.TLSConfig = tlsConfig.Clone()
			if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
				closeListeners(listeners)
				return fmt.Errorf("configure HTTP/2 server: %w", err)
			}
			serveListener = tls.NewListener(listener, server.TLSConfig)
		}
		servers[i] = server
		go func() {
			serveErrors <- server.Serve(serveListener)
		}()
	}

	select {
	case <-ctx.Done():
		return shutdownServers(servers, serveErrors)
	case err := <-serveErrors:
		closeServers(servers)
		for range len(servers) - 1 {
			<-serveErrors
		}
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP listener: %w", err)
	}
}

func validateListeners(listeners []net.Listener) error {
	if len(listeners) == 0 {
		return errors.New("no listeners provided")
	}
	for i, listener := range listeners {
		if listener == nil {
			for _, open := range listeners[:i] {
				_ = open.Close()
			}
			return fmt.Errorf("listener %d is nil", i)
		}
	}
	return nil
}

func (s *Server) publishAddrs(listeners []net.Listener) {
	addrs := make([]net.Addr, len(listeners))
	for i, listener := range listeners {
		addrs[i] = listener.Addr()
	}
	s.addrsMu.Lock()
	s.addrs = append(s.addrs, addrs...)
	s.addrsMu.Unlock()
}

func closeListeners(listeners []net.Listener) {
	for _, listener := range listeners {
		_ = listener.Close()
	}
}

func shutdownServers(servers []*http.Server, serveErrors <-chan error) error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	var firstErr error
	for _, server := range servers {
		if err := server.Shutdown(shutdownCtx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		closeServers(servers)
	}

	for range servers {
		err := <-serveErrors
		if err != nil && !errors.Is(err, http.ErrServerClosed) && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return fmt.Errorf("shutdown HTTP listeners: %w", firstErr)
	}
	return nil
}

func closeServers(servers []*http.Server) {
	for _, server := range servers {
		_ = server.Close()
	}
}

func (s *Server) respond(w http.ResponseWriter, r *http.Request) {
	recorder := w.(*statusRecorder)
	request := &recorder.info
	decision := respond.Select(r, request.state.eng, request.state.cfg)
	request.kind = string(decision.Kind)
	request.rule = decision.RuleName
	respond.Write(w, r, decision, request.state.cfg)
}
