package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/config"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/mgmt"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/state"
)

func (s *Server) mux() *http.ServeMux {
	return s.router
}

const testCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

func TestHandlerSecurityHeaders(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, config.AdminConfig{})
	for _, path := range []string{"/login", "/assets/app.css", "/"} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			response := httptest.NewRecorder()

			server.Handler().ServeHTTP(response, request)

			assertSecurityHeaders(t, response.Result())
		})
	}
}

func TestHandlerRoutes(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, config.AdminConfig{})
	credential := saveTestCredential(t, server, "correct horse battery staple")
	if !credential.Verify("correct horse battery staple") {
		t.Fatal("saved test credential did not verify")
	}
	tests := []struct {
		name        string
		path        string
		wantStatus  int
		wantType    string
		wantBody    string
		wantNoStore bool
	}{
		{
			name:        "index",
			path:        "/",
			wantStatus:  http.StatusOK,
			wantType:    "text/html",
			wantBody:    "<!doctype html>",
			wantNoStore: true,
		},
		{
			name:       "stylesheet",
			path:       "/assets/app.css",
			wantStatus: http.StatusOK,
			wantType:   "text/css",
		},
		{
			name:       "javascript module",
			path:       "/assets/api.js",
			wantStatus: http.StatusOK,
			wantType:   "javascript",
		},
		{
			name:       "SVG logo",
			path:       "/assets/logo.svg",
			wantStatus: http.StatusOK,
			wantType:   "image/svg+xml",
		},
		{
			name:       "HTML blocked from public assets",
			path:       "/assets/config.html",
			wantStatus: http.StatusNotFound,
			wantType:   "text/plain",
		},
		{
			name:        "not found",
			path:        "/missing",
			wantStatus:  http.StatusNotFound,
			wantNoStore: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			request.AddCookie(validSessionCookie(t, server))
			response := httptest.NewRecorder()

			server.Handler().ServeHTTP(response, request)

			result := response.Result()
			defer result.Body.Close()
			if result.StatusCode != test.wantStatus {
				t.Fatalf("status = %d, want %d", result.StatusCode, test.wantStatus)
			}
			if got := result.Header.Get("Content-Type"); !strings.Contains(got, test.wantType) {
				t.Errorf("Content-Type = %q, want it to contain %q", got, test.wantType)
			}
			if test.wantNoStore && result.Header.Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", result.Header.Get("Cache-Control"))
			}
			if test.wantBody != "" {
				body, err := io.ReadAll(result.Body)
				if err != nil {
					t.Fatalf("read body: %v", err)
				}
				if !strings.Contains(strings.ToLower(string(body)), test.wantBody) {
					t.Errorf("body = %q, want it to contain %q", body, test.wantBody)
				}
			}
		})
	}
}

func TestAdminPageShowsReleaseCandidateVersion(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	request := httptest.NewRequest(http.MethodGet, "/config", nil)
	request.AddCookie(validSessionCookie(t, server))
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if !strings.Contains(response.Body.String(), `<footer class="app-footer"><span>v1.2.3-RC</span></footer>`) {
		t.Errorf("admin page does not show the normalized RC version: %q", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `rel="icon" href="/assets/logo.svg" type="image/svg+xml"`) {
		t.Errorf("admin page does not use the embedded logo as its favicon: %q", response.Body.String())
	}
}

func TestHandlerRecoversPanic(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, config.AdminConfig{})
	var logs bytes.Buffer
	server.logger = slog.New(slog.NewTextHandler(&logs, nil))
	saveTestCredential(t, server, "correct horse battery staple")
	server.mux().HandleFunc("GET /panic", func(http.ResponseWriter, *http.Request) {
		panic("test panic")
	})
	request := httptest.NewRequest(http.MethodGet, "/panic", nil)
	request.AddCookie(validSessionCookie(t, server))
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}
	assertSecurityHeaders(t, response.Result())
	if got := logs.String(); !strings.Contains(got, "recovered admin handler panic") || !strings.Contains(got, "test panic") || !strings.Contains(got, "stack=") {
		t.Errorf("panic log = %q, want message, panic value, and stack", got)
	}
}

func TestRedirectHandlerUsesHTTPSOrigin(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, config.AdminConfig{
		Listen: "127.0.0.1:8080",
		TLS: config.AdminTLS{
			Enabled:      true,
			Listen:       "127.0.0.1:8443",
			RedirectHTTP: true,
		},
	})
	request := httptest.NewRequest(http.MethodGet, "http://admin.example:8080/settings?tab=tls", nil)
	response := httptest.NewRecorder()

	server.redirectHandler("127.0.0.1:8443").ServeHTTP(response, request)

	result := response.Result()
	if result.StatusCode != http.StatusMovedPermanently && result.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want a 301 or 302 redirect", result.StatusCode)
	}
	if got, want := result.Header.Get("Location"), "https://admin.example:8443/settings?tab=tls"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
	assertSecurityHeaders(t, result)
}

func TestServeReturnsNilAfterContextCancel(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{Listen: "127.0.0.1:0"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx)
	}()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
}

func newTestServer(t *testing.T, adminConfig config.AdminConfig) *Server {
	t.Helper()
	if adminConfig.SessionTTL == 0 {
		adminConfig.SessionTTL = time.Hour
	}
	cfg := &config.Config{Admin: adminConfig}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stateDir, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	server, err := New(Deps{
		Cfg:     func() *config.Config { return cfg },
		Metrics: mgmt.NewMetrics("1.2.3-rc"),
		State:   stateDir,
		Logger:  logger,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return server
}

func performJSONRequest(t *testing.T, server *Server, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(validSessionCookie(t, server))
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "test-csrf"})
	request.Header.Set("X-CSRF-Token", "test-csrf")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func decodeJSON[T any](t *testing.T, response *httptest.ResponseRecorder, target *T) {
	t.Helper()
	if err := json.Unmarshal(response.Body.Bytes(), target); err != nil {
		t.Fatalf("decode response %q: %v", response.Body.String(), err)
	}
}

func saveTestCredential(t *testing.T, server *Server, password string) Credential {
	t.Helper()
	credential, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := SaveCredential(server.deps.State, credential); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	return credential
}

func validSessionCookie(t *testing.T, server *Server) *http.Cookie {
	t.Helper()
	key, err := LoadOrCreateSessionKey(server.deps.State)
	if err != nil {
		t.Fatalf("LoadOrCreateSessionKey: %v", err)
	}
	return &http.Cookie{
		Name: "sr_session",
		Value: SignSession(key, Session{
			User: "admin",
			Exp:  time.Now().Add(time.Hour),
		}),
	}
}

func assertSecurityHeaders(t *testing.T, response *http.Response) {
	t.Helper()
	for name, want := range map[string]string{
		"Content-Security-Policy": testCSP,
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
	} {
		if got := response.Header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}
