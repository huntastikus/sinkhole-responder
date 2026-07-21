package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/huntastikus/sinkhole-responder/internal/config"
)

func TestTLSPageIsServedToAuthenticatedUsers(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, testAdminPassword)

	request := httptest.NewRequest(http.MethodGet, "/tls", nil)
	request.AddCookie(validSessionCookie(t, server))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", response.Code, http.StatusOK, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", got)
	}
	for _, want := range []string{`/assets/tls.js`, `id="tls-mode"`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Errorf("body does not contain %q", want)
		}
	}
	assertSecurityHeaders(t, response.Result())
}

func TestTLSPageRequiresAuthentication(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, testAdminPassword)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/tls", nil))

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
		t.Fatalf("response = %d Location=%q, want 303 /login", response.Code, response.Header().Get("Location"))
	}
}

func TestTrustStoreGuidesAreServed(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, testAdminPassword)
	cookie := validSessionCookie(t, server)

	for _, test := range []struct {
		platform string
		marker   string
	}{
		{platform: "windows", marker: "certutil -addstore"},
		{platform: "macos", marker: "security add-trusted-cert"},
		{platform: "ios", marker: "Certificate Trust Settings"},
		{platform: "android", marker: "Encryption &amp; credentials"},
		{platform: "debian", marker: "update-ca-certificates"},
		{platform: "firefox", marker: "Authorities"},
		{platform: "chrome", marker: "nssdb"},
	} {
		t.Run(test.platform, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/help/trust-"+test.platform, nil)
			request.AddCookie(cookie)
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body=%q", response.Code, http.StatusOK, response.Body.String())
			}
			if got := response.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
				t.Errorf("Content-Type = %q, want text/html", got)
			}
			body := response.Body.String()
			for _, want := range []string{test.marker, "lab/home"} {
				if !strings.Contains(body, want) {
					t.Errorf("body does not contain %q", want)
				}
			}
			assertSecurityHeaders(t, response.Result())
		})
	}

	request := httptest.NewRequest(http.MethodGet, "/help/trust-plan9", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown platform status = %d, want %d", response.Code, http.StatusNotFound)
	}
}
