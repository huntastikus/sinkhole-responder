package respond

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/config"
)

const (
	maxResponseDelay = 10 * time.Second
	allowedMethods   = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"
)

// Write emits a selected response and its standard sinkhole headers.
func Write(w http.ResponseWriter, r *http.Request, d Decision, cfg *config.Config) {
	if w == nil || !waitForDelay(r, d.Delay) {
		return
	}
	if isPreflight(r) {
		WritePreflight(w, r)
		return
	}

	status := d.Status
	if status < 100 || status > 999 {
		status = http.StatusOK
	}
	noBody := status == http.StatusNoContent || status == http.StatusNotModified
	header := w.Header()
	if !noBody {
		if d.ContentType != "" {
			header.Set("Content-Type", d.ContentType)
		} else {
			header.Del("Content-Type")
		}
		header.Set("Content-Length", strconv.Itoa(len(d.Body)))
	}
	setCORSHeaders(header, r)
	header.Set("Cross-Origin-Resource-Policy", "cross-origin")
	header.Set("Timing-Allow-Origin", "*")
	header.Set("Cache-Control", cacheControl(cfg))
	// X-Sinkhole is a deliberately small marker that lets operators confirm
	// that this responder, rather than the blocked origin, answered a request.
	header.Set("X-Sinkhole", "1")
	setExtraHeaders(header, d.ExtraHeaders)

	// Protocol and security invariants take precedence over rule overrides.
	header.Del("Set-Cookie")
	if noBody {
		header.Del("Content-Type")
		header.Del("Content-Length")
	}

	w.WriteHeader(status)
	if noBody || (r != nil && strings.EqualFold(r.Method, http.MethodHead)) {
		return
	}
	_, _ = w.Write(d.Body)
}

// WritePreflight emits the fixed permissive CORS preflight response.
func WritePreflight(w http.ResponseWriter, r *http.Request) {
	if w == nil {
		return
	}
	header := w.Header()
	setCORSHeaders(header, r)
	header.Set("Access-Control-Allow-Methods", allowedMethods)
	requestedHeaders := ""
	if r != nil {
		requestedHeaders = r.Header.Get("Access-Control-Request-Headers")
	}
	if requestedHeaders == "" {
		requestedHeaders = "*"
	}
	header.Set("Access-Control-Allow-Headers", requestedHeaders)
	header.Set("Access-Control-Max-Age", "86400")
	addVary(header, "Origin")
	header.Del("Content-Type")
	header.Del("Content-Length")
	header.Del("Set-Cookie")
	w.WriteHeader(http.StatusNoContent)
}

func waitForDelay(r *http.Request, delay time.Duration) bool {
	if delay <= 0 {
		return true
	}
	if delay > maxResponseDelay {
		delay = maxResponseDelay
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()
	if r == nil {
		<-timer.C
		return true
	}
	select {
	case <-timer.C:
		return true
	case <-r.Context().Done():
		return false
	}
}

func isPreflight(r *http.Request) bool {
	return r != nil && strings.EqualFold(r.Method, http.MethodOptions) &&
		r.Header.Get("Access-Control-Request-Method") != ""
}

func setCORSHeaders(header http.Header, r *http.Request) {
	origin := ""
	if r != nil {
		origin = r.Header.Get("Origin")
	}
	if origin == "" {
		header.Set("Access-Control-Allow-Origin", "*")
		header.Del("Access-Control-Allow-Credentials")
		return
	}

	// Sinkhole responses contain only static placeholders and no user data, so
	// echoing Origin with credentials is safe and lets credentialed blocked
	// fetches complete without causing page-level failures.
	header.Set("Access-Control-Allow-Origin", origin)
	header.Set("Access-Control-Allow-Credentials", "true")
	addVary(header, "Origin")
}

func addVary(header http.Header, value string) {
	for _, existing := range header.Values("Vary") {
		for _, field := range strings.Split(existing, ",") {
			if strings.EqualFold(strings.TrimSpace(field), value) {
				return
			}
		}
	}
	header.Add("Vary", value)
}

func setExtraHeaders(header http.Header, extra map[string]string) {
	for key, value := range extra {
		header.Set(key, value)
	}
}

func cacheControl(cfg *config.Config) string {
	if cfg == nil {
		return "no-store"
	}
	return cfg.Defaults.CacheControl
}
