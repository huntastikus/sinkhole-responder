package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/huntastikus/sinkhole-responder/internal/config"
)

func TestDetectorPageIsServedToAuthenticatedUsers(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, testAdminPassword)

	request := httptest.NewRequest(http.MethodGet, "/tools/detector", nil)
	request.AddCookie(validSessionCookie(t, server))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", response.Code, http.StatusOK, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", got)
	}
	for _, want := range []string{`/assets/app.css`, `/assets/detector.js`, `/rulepacks`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Errorf("body does not contain %q", want)
		}
	}
	assertSecurityHeaders(t, response.Result())
}

func TestDetectorPageRequiresAuthentication(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, testAdminPassword)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/tools/detector", nil))

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
		t.Fatalf("response = %d Location=%q, want 303 /login", response.Code, response.Header().Get("Location"))
	}
}
