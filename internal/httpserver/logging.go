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
	s.metrics.ObserveRequest(info.kind, info.rule, status, duration)
	logAccess(s.accessLogger, info.state.cfg, r, info.rule, info.kind, status, duration, info.requestBody)
}

func logAccess(logger *slog.Logger, cfg *config.Config, r *http.Request, rule, kind string, status int, duration time.Duration, requestBody *requestBodyLog) {
	if cfg != nil && cfg.Logging.AccessLog != nil && !*cfg.Logging.AccessLog {
		return
	}

	attrs := make([]slog.Attr, 0, 13)
	attrs = append(attrs,
		slog.String("method", r.Method),
		slog.String("host", normalizedHost(r.Host)),
		slog.String("path", requestPath(r)),
	)
	if cfg != nil && cfg.Logging.LogQuery && r.URL != nil {
		attrs = append(attrs, slog.String("query", r.URL.RawQuery))
	}
	if rule != "" {
		attrs = append(attrs, slog.String("rule", rule))
	}
	attrs = append(attrs, requestBodyLogAttrs(requestBody)...)
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

func requestBodyLogAttrs(body *requestBodyLog) []slog.Attr {
	if body == nil {
		return nil
	}
	attrs := make([]slog.Attr, 0, 3)
	if body.omitted != "" {
		attrs = append(attrs, slog.String("request_body_omitted", body.omitted))
	} else {
		attrs = append(attrs, slog.String("request_body", body.value))
	}
	if body.truncated {
		attrs = append(attrs, slog.Bool("request_body_truncated", true))
	}
	if body.redacted {
		attrs = append(attrs, slog.Bool("request_body_redacted", true))
	}
	return attrs
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
