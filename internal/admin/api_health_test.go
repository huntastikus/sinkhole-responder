package admin

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/huntastikus/sinkhole-responder/internal/config"
	"github.com/huntastikus/sinkhole-responder/internal/logbuf"
	"github.com/huntastikus/sinkhole-responder/internal/state"
)

func TestSystemHealthGreen(t *testing.T) {
	cfg := greenHealthConfig()
	server, _ := newHealthTestServer(t, cfg)

	response := requestSystemHealth(t, server.mux())
	if response.Overall != healthGreen {
		t.Fatalf("overall = %q, want %q", response.Overall, healthGreen)
	}

	for _, name := range []string{"listeners", "tls", "state_dir", "recent_errors", "rulepacks"} {
		check := findHealthCheck(t, response, name)
		if check.Status != healthGreen {
			t.Errorf("check %q status = %q, want %q (detail %q)", name, check.Status, healthGreen, check.Detail)
		}
	}
}

func TestSystemHealthUnwritableStateDir(t *testing.T) {
	cfg := greenHealthConfig()
	server, stateDir := newHealthTestServer(t, cfg)
	stateDir.Root = filepath.Join(t.TempDir(), "missing", "state")

	response := requestSystemHealth(t, server.mux())
	check := findHealthCheck(t, response, "state_dir")
	if check.Status != healthRed {
		t.Errorf("state_dir status = %q, want %q", check.Status, healthRed)
	}
	if check.Detail != "config save disabled" {
		t.Errorf("state_dir detail = %q, want %q", check.Detail, "config save disabled")
	}
	if response.Overall != healthRed {
		t.Errorf("overall = %q, want %q", response.Overall, healthRed)
	}
}

func TestSystemHealthRecentErrorsRed(t *testing.T) {
	cfg := greenHealthConfig()
	server, _ := newHealthTestServer(t, cfg)
	logger := slog.New(server.deps.LogBuf.Handler(slog.NewTextHandler(io.Discard, nil)))
	for range 5 {
		logger.ErrorContext(context.Background(), "test error")
	}

	response := requestSystemHealth(t, server.mux())
	check := findHealthCheck(t, response, "recent_errors")
	if check.Status != healthRed {
		t.Errorf("recent_errors status = %q, want %q", check.Status, healthRed)
	}
	if check.Detail != "5 recent errors" {
		t.Errorf("recent_errors detail = %q, want %q", check.Detail, "5 recent errors")
	}
	if response.Overall != healthRed {
		t.Errorf("overall = %q, want %q", response.Overall, healthRed)
	}
}

func TestSystemHealthNoRulepacksAmber(t *testing.T) {
	cfg := greenHealthConfig()
	cfg.Rulepacks.Enabled = nil
	server, _ := newHealthTestServer(t, cfg)

	response := requestSystemHealth(t, server.mux())
	check := findHealthCheck(t, response, "rulepacks")
	if check.Status != healthAmber {
		t.Errorf("rulepacks status = %q, want %q", check.Status, healthAmber)
	}
	if check.Detail != "no adblock packs enabled" {
		t.Errorf("rulepacks detail = %q, want %q", check.Detail, "no adblock packs enabled")
	}
	if response.Overall != healthAmber {
		t.Errorf("overall = %q, want %q", response.Overall, healthAmber)
	}
}

func TestSystemHealthRequiresAuthentication(t *testing.T) {
	server, _ := newHealthTestServer(t, greenHealthConfig())
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/system/health", nil)

	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusSeeOther)
	}
	if location := recorder.Header().Get("Location"); location != "/login" {
		t.Errorf("Location = %q, want %q", location, "/login")
	}
}

func TestTLSHealthLocalCA(t *testing.T) {
	cases := []struct {
		name       string
		cert, key  string
		wantStatus healthStatus
		wantDetail string
	}{
		{"auto-generated", "", "", healthGreen, "local CA (auto-generated)"},
		{"configured", "/tls/ca.cert.pem", "/tls/ca.key.pem", healthGreen, "local CA configured"},
		{"cert only", "/tls/ca.cert.pem", "", healthRed, "local CA paths must be set together"},
		{"key only", "", "/tls/ca.key.pem", healthRed, "local CA paths must be set together"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.TLS.Mode = "local-ca"
			cfg.TLS.LocalCA.CACert = tc.cert
			cfg.TLS.LocalCA.CAKey = tc.key
			check := tlsHealth(cfg)
			if check.Status != tc.wantStatus || check.Detail != tc.wantDetail {
				t.Fatalf("tlsHealth = {%q, %q}, want {%q, %q}", check.Status, check.Detail, tc.wantStatus, tc.wantDetail)
			}
		})
	}
}

func greenHealthConfig() *config.Config {
	return &config.Config{
		Listen: config.ListenConfig{HTTP: []string{"127.0.0.1:8081"}},
		TLS: config.TLSConfig{
			Mode: "static",
			Static: config.TLSStatic{Certs: []config.CertPair{{
				CertFile: "server.crt",
				KeyFile:  "server.key",
			}}},
		},
		Admin: config.AdminConfig{
			Listen:         "127.0.0.1:8080",
			LoginRatePerIP: 1,
			LoginBurst:     1,
		},
		Rulepacks: config.RulepacksConfig{Enabled: []string{"recommended"}},
	}
}

func newHealthTestServer(t *testing.T, cfg *config.Config) (*Server, *state.Dir) {
	t.Helper()
	stateDir, err := state.New(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	credential, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := SaveCredential(stateDir, credential); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	ring := logbuf.NewRing(50)
	server, err := New(Deps{
		Cfg:    func() *config.Config { return cfg },
		State:  stateDir,
		LogBuf: ring,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return server, stateDir
}

func requestSystemHealth(t *testing.T, handler http.Handler) healthResponse {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/system/health", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response healthResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return response
}

func findHealthCheck(t *testing.T, response healthResponse, name string) healthCheck {
	t.Helper()
	for _, check := range response.Checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("health check %q not found in %#v", name, response.Checks)
	return healthCheck{}
}
