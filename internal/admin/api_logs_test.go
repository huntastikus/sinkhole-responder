package admin

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/config"
	"github.com/huntastikus/sinkhole-responder/internal/logbuf"
)

func TestLogsFiltersByLevelAndReturnsNewestFirst(t *testing.T) {
	server := newLogsTestServer(t)
	response := performJSONRequest(t, server, http.MethodGet, "/api/logs?level=warn", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	body := decodeLogsResponse(t, response)
	wantMessages := []string{"error-6", "warn-5", "error-3", "warn-2"}
	if len(body.Records) != len(wantMessages) {
		t.Fatalf("record count = %d, want %d", len(body.Records), len(wantMessages))
	}
	for index, want := range wantMessages {
		if body.Records[index].Msg != want {
			t.Errorf("records[%d].msg = %q, want %q", index, body.Records[index].Msg, want)
		}
		if _, err := time.Parse(time.RFC3339, body.Records[index].Time); err != nil {
			t.Errorf("records[%d].time = %q, want RFC3339: %v", index, body.Records[index].Time, err)
		}
	}
	if got := body.Records[0].Attrs["query"]; got != "[REDACTED]" {
		t.Errorf("redacted query attr = %#v, want [REDACTED]", got)
	}
	if strings.Contains(response.Body.String(), "secret=one") {
		t.Error("response exposed the original query value")
	}
}

func TestLogsAppliesLimit(t *testing.T) {
	server := newLogsTestServer(t)
	response := performJSONRequest(t, server, http.MethodGet, "/api/logs?limit=5", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	body := decodeLogsResponse(t, response)
	wantMessages := []string{"info-7", "error-6", "warn-5", "info-4", "error-3"}
	if len(body.Records) != len(wantMessages) {
		t.Fatalf("record count = %d, want %d", len(body.Records), len(wantMessages))
	}
	for index, want := range wantMessages {
		if body.Records[index].Msg != want {
			t.Errorf("records[%d].msg = %q, want %q", index, body.Records[index].Msg, want)
		}
	}
}

func TestLogsRejectsInvalidLevel(t *testing.T) {
	server := newLogsTestServer(t)
	response := performJSONRequest(t, server, http.MethodGet, "/api/logs?level=trace", nil)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusBadRequest, response.Body.String())
	}
}

func TestLogsReturnsEmptyArrayWithoutBuffer(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	response := performJSONRequest(t, server, http.MethodGet, "/api/logs", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	body := decodeLogsResponse(t, response)
	if body.Records == nil || len(body.Records) != 0 {
		t.Errorf("records = %#v, want empty array", body.Records)
	}
}

func TestLogsRequiresAuthentication(t *testing.T) {
	server := newLogsTestServer(t)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/logs", nil))

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
		t.Errorf("status/location = %d/%q, want %d/%q", response.Code, response.Header().Get("Location"), http.StatusSeeOther, "/login")
	}
}

func TestLogsPageIsEmbeddedAndCSPProtected(t *testing.T) {
	server := newLogsTestServer(t)
	response := performJSONRequest(t, server, http.MethodGet, "/logs", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", contentType)
	}
	if !strings.Contains(response.Body.String(), "/assets/logs.js") {
		t.Errorf("page does not load /assets/logs.js: %q", response.Body.String())
	}
	if csp := response.Header().Get("Content-Security-Policy"); csp != contentSecurityPolicy {
		t.Errorf("Content-Security-Policy = %q, want %q", csp, contentSecurityPolicy)
	}
}

func newLogsTestServer(t *testing.T) *Server {
	t.Helper()
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")

	ring := logbuf.NewRing(20)
	handler := ring.Handler(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	baseTime := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	levels := []slog.Level{
		slog.LevelDebug,
		slog.LevelInfo,
		slog.LevelWarn,
		slog.LevelError,
		slog.LevelInfo,
		slog.LevelWarn,
		slog.LevelError,
		slog.LevelInfo,
	}
	for index, level := range levels {
		record := slog.NewRecord(baseTime.Add(time.Duration(index)*time.Second), level, strings.ToLower(level.String())+"-"+string(rune('0'+index)), 0)
		record.AddAttrs(slog.String("query", "[REDACTED]"))
		if err := handler.Handle(context.Background(), record); err != nil {
			t.Fatalf("seed log record: %v", err)
		}
	}
	server.deps.LogBuf = ring
	return server
}

func decodeLogsResponse(t *testing.T, response *httptest.ResponseRecorder) logsResponse {
	t.Helper()
	var body logsResponse
	decodeJSON(t, response, &body)
	return body
}
