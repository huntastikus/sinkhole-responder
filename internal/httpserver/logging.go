package httpserver

import (
	"context"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/config"
	"golang.org/x/net/idna"
)

func (s *Server) finishRequest(recorder *statusRecorder, r *http.Request, info *requestInfo) {
	status := recorder.status
	if status == 0 {
		status = http.StatusOK
	}
	duration := time.Since(info.start)
	s.metrics.ObserveRequest(info.kind, status, duration)
	logAccess(s.accessLogger, info.state.cfg, r, info.rule, info.kind, status, duration)
}

func logAccess(logger *slog.Logger, cfg *config.Config, r *http.Request, rule, kind string, status int, duration time.Duration) {
	if cfg != nil && cfg.Logging.AccessLog != nil && !*cfg.Logging.AccessLog {
		return
	}

	attrs := make([]slog.Attr, 0, 8)
	attrs = append(attrs,
		slog.String("host", normalizedHost(r.Host)),
		slog.String("path", requestPath(r)),
	)
	if cfg != nil && cfg.Logging.LogQuery && r.URL != nil {
		attrs = append(attrs, slog.String("query", r.URL.RawQuery))
	}
	if rule != "" {
		attrs = append(attrs, slog.String("rule", rule))
	}
	attrs = append(attrs,
		slog.String("kind", kind),
		slog.Int("status", status),
		slog.Float64("duration_ms", math.Round(float64(duration)/float64(time.Millisecond)*10)/10),
		slog.String("client", loggedClient(r.RemoteAddr, anonymizeClients(cfg))),
	)
	logger.LogAttrs(context.Background(), slog.LevelInfo, "request", attrs...)
}

func requestPath(r *http.Request) string {
	if r.URL == nil {
		return ""
	}
	return r.URL.Path
}

func normalizedHost(raw string) string {
	host := raw
	if split, _, err := net.SplitHostPort(raw); err == nil {
		host = split
	} else if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ascii, err := idna.Lookup.ToASCII(host); err == nil {
		return ascii
	}
	return host
}

func anonymizeClients(cfg *config.Config) bool {
	return cfg == nil || cfg.Logging.AnonymizeClient == nil || *cfg.Logging.AnonymizeClient
}

func loggedClient(remoteAddress string, anonymize bool) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return "unknown"
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return "unknown"
	}
	address = address.Unmap()
	if !anonymize {
		return address.String()
	}
	if address.Is4() {
		bytes := address.As4()
		bytes[3] = 0
		return netip.AddrFrom4(bytes).String() + "/24"
	}
	bytes := address.As16()
	for i := 6; i < len(bytes); i++ {
		bytes[i] = 0
	}
	return netip.AddrFrom16(bytes).String() + "/48"
}
