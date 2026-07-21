package httpserver

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/huntastikus/sinkhole-responder/internal/config"
)

func FuzzHostHeader(f *testing.F) {
	for _, host := range []string{
		"example.com",
		"bücher.example",
		"xn--bcher-kva.example",
		"example.com.",
		"example.com:8080",
		"[2001:db8::1]",
		"[2001:db8::1]:443",
		"",
		":",
		"[[[",
		strings.Repeat("a", 64<<10),
		"a\x00b",
		"xn--",
		"%00",
		"a\r\nX: y",
	} {
		f.Add(host)
	}

	cfg := &config.Config{
		Defaults: config.DefaultsConfig{
			Status:        http.StatusOK,
			BeaconStatus:  http.StatusOK,
			MediaResponse: "204",
			CacheControl:  "no-store",
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := New(cfg, nil, logger, nil).Handler()

	f.Fuzz(func(t *testing.T, host string) {
		request := httptest.NewRequest(http.MethodGet, "http://placeholder.test/", nil)
		request.Host = host
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code == 0 {
			t.Fatal("handler did not write a status")
		}
	})
}
