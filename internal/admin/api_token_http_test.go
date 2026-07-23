package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/huntastikus/sinkhole-responder/internal/config"
)

type apiTokenStatusResponse struct {
	Present   bool   `json:"present"`
	CreatedAt string `json:"created_at"`
	Token     string `json:"token"`
}

func TestAPITokenHTTPLifecycleAndBearerScope(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")

	create := performJSONRequest(t, server, http.MethodPost, "/api/admin/token", nil)
	if create.Code != http.StatusOK {
		t.Fatalf("create status = %d, want %d; body = %q", create.Code, http.StatusOK, create.Body.String())
	}
	var created apiTokenStatusResponse
	decodeJSON(t, create, &created)
	if !strings.HasPrefix(created.Token, "srt_") || created.CreatedAt == "" {
		t.Fatalf("create response = %#v, want token and created_at", created)
	}

	status := performJSONRequest(t, server, http.MethodGet, "/api/admin/token", nil)
	if status.Code != http.StatusOK {
		t.Fatalf("status GET = %d, want %d", status.Code, http.StatusOK)
	}
	var current apiTokenStatusResponse
	decodeJSON(t, status, &current)
	if !current.Present || current.CreatedAt == "" || current.Token != "" || strings.Contains(status.Body.String(), created.Token) {
		t.Fatalf("status response exposed or omitted token state: %#v", current)
	}

	bearerRequest := func(method, path, token string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	if response := bearerRequest(http.MethodGet, "/api/stats", created.Token); response.Code != http.StatusOK {
		t.Fatalf("bearer stats status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	if response := bearerRequest(http.MethodPut, "/api/config", created.Token); response.Code != http.StatusSeeOther {
		t.Fatalf("bearer config PUT status = %d, want %d", response.Code, http.StatusSeeOther)
	}
	if response := bearerRequest(http.MethodPost, "/api/system/restart", created.Token); response.Code != http.StatusSeeOther {
		t.Fatalf("bearer restart POST status = %d, want %d", response.Code, http.StatusSeeOther)
	}
	if response := bearerRequest(http.MethodGet, "/api/stats", "srt_wrong"); response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong bearer status = %d, want %d", response.Code, http.StatusUnauthorized)
	}

	revoke := performJSONRequest(t, server, http.MethodDelete, "/api/admin/token", nil)
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want %d; body = %q", revoke.Code, http.StatusOK, revoke.Body.String())
	}
	if response := bearerRequest(http.MethodGet, "/api/stats", created.Token); response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked bearer status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestAPITokenAllowsOnlyDocumentedReadPaths(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	plaintext, stored, err := GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveAPIToken(server.deps.State, stored); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/stats", "/api/stats/history", "/api/system/health", "/api/logs"} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.Header.Set("Authorization", "Bearer "+plaintext)
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code == http.StatusSeeOther || response.Code == http.StatusUnauthorized {
				t.Fatalf("GET %s bearer status = %d, want authenticated handler response", path, response.Code)
			}
		})
	}
}

func TestAPITokenStatusJSONNeverContainsStoredHash(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	_, stored, err := GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveAPIToken(server.deps.State, stored); err != nil {
		t.Fatal(err)
	}
	response := performJSONRequest(t, server, http.MethodGet, "/api/admin/token", nil)
	var decoded map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(response.Body.String(), stored.HashB64) {
		t.Fatal("status response contains stored token hash")
	}
}
