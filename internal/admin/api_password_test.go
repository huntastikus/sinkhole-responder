package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/huntastikus/sinkhole-responder/internal/config"
)

func TestPasswordChangeRejectsWrongCurrentPassword(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	body, err := json.Marshal(map[string]string{
		"current_password": "wrong password",
		"new_password":     "another secure password",
	})
	if err != nil {
		t.Fatal(err)
	}

	response := performJSONRequest(t, server, http.MethodPost, "/api/admin/password", body)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusUnauthorized, response.Body.String())
	}
	credential, present, err := LoadCredential(server.deps.State)
	if err != nil || !present || !credential.Verify("correct horse battery staple") {
		t.Fatalf("credential changed after rejected request: present=%v err=%v", present, err)
	}
}

func TestPasswordChangeRejectsShortNewPassword(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	body, err := json.Marshal(map[string]string{
		"current_password": "correct horse battery staple",
		"new_password":     "short",
	})
	if err != nil {
		t.Fatal(err)
	}

	response := performJSONRequest(t, server, http.MethodPost, "/api/admin/password", body)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusBadRequest, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "at least") {
		t.Errorf("body = %q, want minimum-length error", response.Body.String())
	}
}

func TestPasswordChangeRotatesSessionsAndKeepsCallerSignedIn(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	oldSession := validSessionCookie(t, server)
	body, err := json.Marshal(map[string]string{
		"current_password": "correct horse battery staple",
		"new_password":     "another secure password",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/admin/password", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(oldSession)
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "test-csrf"})
	request.Header.Set("X-CSRF-Token", "test-csrf")
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	newSession := findResponseCookie(t, response.Result(), sessionCookieName)
	if newSession.Value == oldSession.Value {
		t.Fatal("password change reissued the old session")
	}

	oldRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	oldRequest.AddCookie(oldSession)
	oldResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(oldResponse, oldRequest)
	assertRedirect(t, oldResponse.Result(), "/login")

	newRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	newRequest.AddCookie(newSession)
	newResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(newResponse, newRequest)
	if newResponse.Code != http.StatusOK {
		t.Fatalf("new session GET / status = %d, want %d", newResponse.Code, http.StatusOK)
	}

	credential, present, err := LoadCredential(server.deps.State)
	if err != nil || !present || !credential.Verify("another secure password") || credential.Verify("correct horse battery staple") {
		t.Fatalf("stored credential did not change correctly: present=%v err=%v", present, err)
	}
}
