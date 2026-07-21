package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/huntastikus/sinkhole-responder/internal/config"
)

func TestLANIPRequiresAuthentication(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/system/lan-ip", nil))

	assertRedirect(t, response.Result(), "/login")
}

func TestLANIPReturnsInterfaceAddresses(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	request := httptest.NewRequest(http.MethodGet, "/api/system/lan-ip", nil)
	request.AddCookie(validSessionCookie(t, server))
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	var body struct {
		IPs []struct {
			Addr   string `json:"addr"`
			Iface  string `json:"iface"`
			Family string `json:"family"`
		} `json:"ips"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.IPs == nil {
		t.Fatal("ips = nil, want a JSON array")
	}
	seenIPv6 := false
	for _, entry := range body.IPs {
		if entry.Addr == "" || entry.Iface == "" {
			t.Errorf("entry = %+v, want non-empty addr and iface", entry)
		}
		if entry.Family != "ipv4" && entry.Family != "ipv6" {
			t.Errorf("entry family = %q, want ipv4 or ipv6", entry.Family)
		}
		if entry.Addr == "127.0.0.1" || entry.Addr == "::1" {
			t.Errorf("loopback address %q was included", entry.Addr)
		}
		if entry.Family == "ipv6" {
			seenIPv6 = true
		} else if seenIPv6 {
			t.Error("IPv4 entry appears after an IPv6 entry")
		}
	}
}

func TestWizardPageRequiresAuthentication(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/wizard", nil))

	assertRedirect(t, response.Result(), "/login")
}

func TestWizardPage(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	request := httptest.NewRequest(http.MethodGet, "/wizard", nil)
	request.AddCookie(validSessionCookie(t, server))
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	result := response.Result()
	if result.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", result.StatusCode, http.StatusOK)
	}
	if got := result.Header.Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", got)
	}
	if !strings.Contains(response.Body.String(), "wizard.js") {
		t.Errorf("body does not reference wizard.js")
	}
	assertSecurityHeaders(t, result)
}

func TestFirstRunSetupRedirectsToWizardAndKeepsAuthCookies(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	response := performFormRequest(server, http.MethodPost, "/setup", "password", "correct horse battery staple", "192.0.2.1:1234")

	assertRedirect(t, response.Result(), "/wizard")
	findResponseCookie(t, response.Result(), sessionCookieName)
	findResponseCookie(t, response.Result(), csrfCookieName)
}

func TestExistingSetupAndLoginRedirectsAreUnchanged(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")

	setupResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(setupResponse, httptest.NewRequest(http.MethodGet, "/setup", nil))
	assertRedirect(t, setupResponse.Result(), "/")

	loginResponse := performFormRequest(server, http.MethodPost, "/login", "password", "correct horse battery staple", "192.0.2.1:1234")
	assertRedirect(t, loginResponse.Result(), "/")
	findResponseCookie(t, loginResponse.Result(), sessionCookieName)
}
