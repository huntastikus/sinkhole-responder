package mgmt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/config"
)

const (
	metricsContentType = "text/plain; version=0.0.4; charset=utf-8"
	shutdownTimeout    = 2 * time.Second
)

// Serve runs the management listener until ctx is canceled.
func Serve(ctx context.Context, cfg *config.Config, m *Metrics, logger *slog.Logger) error {
	if cfg == nil {
		return errors.New("management configuration is nil")
	}
	logger = managementLogger(logger)
	if cfg.Management.Enabled != nil && !*cfg.Management.Enabled {
		logger.Info("management listener disabled")
		return nil
	}
	if err := config.ValidateManagementListen(cfg.Management.Listen, cfg.Management.AllowExternal); err != nil {
		return err
	}

	listener, err := net.Listen("tcp", cfg.Management.Listen)
	if err != nil {
		return fmt.Errorf("bind management listener: %w", err)
	}
	return ServeListener(ctx, listener, m, logger)
}

// ServeListener serves management endpoints on an already-bound listener.
func ServeListener(ctx context.Context, listener net.Listener, m *Metrics, logger *slog.Logger) error {
	logger = managementLogger(logger)
	server := &http.Server{
		Handler:        managementHandler(m),
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		IdleTimeout:    30 * time.Second,
		MaxHeaderBytes: 8 * 1024,
	}

	logger.Info("management listener started", "addr", listener.Addr().String())
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(listener)
	}()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			<-serveErr
			return fmt.Errorf("shutdown management listener: %w", err)
		}
		err := <-serveErr
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func managementHandler(m *Metrics) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		switch r.URL.Path {
		case "/healthz":
			w.Header().Set("Content-Type", "application/json")
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte("{\"status\":\"ok\"}\n"))
			}
		case "/metrics":
			w.Header().Set("Content-Type", metricsContentType)
			if r.Method == http.MethodGet {
				m.WritePrometheus(w)
			}
		default:
			http.NotFound(w, r)
		}
	})
}

func managementLogger(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return slog.Default()
	}
	return logger
}
