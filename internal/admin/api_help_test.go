package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/config"
)

func TestHelpTopicsAreServed(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, testAdminPassword)
	cookie := validSessionCookie(t, server)

	for _, test := range []struct {
		slug    string
		heading string
	}{
		{slug: "quick-start", heading: "Quick start"},
		{slug: "adguard-home", heading: "AdGuard Home setup"},
		{slug: "tls-trust", heading: "TLS and trusting the CA"},
		{slug: "rules-rulepacks", heading: "Rules and rulepacks"},
		{slug: "adblock-limits", heading: "Adblock-defeat explained + honest limits"},
		{slug: "security", heading: "Security and hardening"},
		{slug: "troubleshooting", heading: "Troubleshooting"},
	} {
		t.Run(test.slug, func(t *testing.T) {
			response := authenticatedHelpRequest(t, server, cookie, "/help/"+test.slug)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body=%q", response.Code, http.StatusOK, response.Body.String())
			}
			if got := response.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
				t.Errorf("Content-Type = %q, want text/html", got)
			}
			for _, want := range []string{test.heading, `/assets/app.css`, `/assets/nav.js`} {
				if !strings.Contains(response.Body.String(), want) {
					t.Errorf("body does not contain %q", want)
				}
			}
			assertSecurityHeaders(t, response.Result())
		})
	}
}

func TestHelpIndexListsAllTopicsAndTrustGuides(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, testAdminPassword)
	response := authenticatedHelpRequest(t, server, validSessionCookie(t, server), "/help/")

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", response.Code, http.StatusOK, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", got)
	}
	for _, path := range []string{
		"/help/quick-start",
		"/help/adguard-home",
		"/help/tls-trust",
		"/help/rules-rulepacks",
		"/help/adblock-limits",
		"/help/security",
		"/help/troubleshooting",
		"/help/trust-windows",
		"/help/trust-macos",
		"/help/trust-ios",
		"/help/trust-android",
		"/help/trust-debian",
		"/help/trust-firefox",
		"/help/trust-chrome",
	} {
		if !strings.Contains(response.Body.String(), `href="`+path+`"`) {
			t.Errorf("body does not link to %q", path)
		}
	}
	for _, want := range []string{"Help center", `/assets/app.css`, `/assets/nav.js`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Errorf("body does not contain %q", want)
		}
	}
	assertSecurityHeaders(t, response.Result())
}

func TestHelpLimitsPageContainsCannotList(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, testAdminPassword)
	response := authenticatedHelpRequest(t, server, validSessionCookie(t, server), "/help/adblock-limits")
	body := strings.ToLower(response.Body.String())

	for _, marker := range []string{"first-party", "impression"} {
		if !strings.Contains(body, marker) {
			t.Errorf("limits page does not contain %q", marker)
		}
	}
	if !strings.Contains(body, "subresource integrity") && !strings.Contains(body, "sri") {
		t.Error("limits page does not contain Subresource Integrity or SRI")
	}
}

func TestHelpRoutesRejectUnknownAndUnauthenticatedRequests(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, testAdminPassword)

	unknown := authenticatedHelpRequest(t, server, validSessionCookie(t, server), "/help/does-not-exist")
	if unknown.Code != http.StatusNotFound {
		t.Errorf("unknown topic status = %d, want %d", unknown.Code, http.StatusNotFound)
	}

	unauthenticated := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/help/quick-start", nil))
	if unauthenticated.Code != http.StatusSeeOther || unauthenticated.Header().Get("Location") != "/login" {
		t.Errorf("unauthenticated response = %d Location=%q, want 303 /login", unauthenticated.Code, unauthenticated.Header().Get("Location"))
	}

	trustGuide := authenticatedHelpRequest(t, server, validSessionCookie(t, server), "/help/trust-macos")
	if trustGuide.Code != http.StatusOK {
		t.Errorf("trust guide status = %d, want %d", trustGuide.Code, http.StatusOK)
	}
}

func authenticatedHelpRequest(t *testing.T, server *Server, cookie *http.Cookie, path string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}
