package admin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/config"
)

func TestFirstRunRedirectsAppToSetup(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	assertRedirect(t, response.Result(), "/setup")
}

func TestLoginShowsReleaseCandidateVersion(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, config.AdminConfig{})
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/login", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if !strings.Contains(response.Body.String(), `<p class="auth-version">v1.2.3-RC</p>`) {
		t.Errorf("login page does not show the normalized RC version: %q", response.Body.String())
	}
}

func TestSetupCreatesCredentialAndSession(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{
		SessionTTL: time.Hour,
		TLS:        config.AdminTLS{Enabled: true},
	})
	response := performFormRequest(server, http.MethodPost, "/setup", "password", "correct horse battery staple", "192.0.2.1:1234")

	assertRedirect(t, response.Result(), "/wizard")
	sessionCookie := findResponseCookie(t, response.Result(), "sr_session")
	csrfCookie := findResponseCookie(t, response.Result(), "sr_csrf")
	if !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteStrictMode || !sessionCookie.Secure || sessionCookie.Path != "/" {
		t.Errorf("session cookie attributes = HttpOnly:%v SameSite:%v Secure:%v Path:%q", sessionCookie.HttpOnly, sessionCookie.SameSite, sessionCookie.Secure, sessionCookie.Path)
	}
	if csrfCookie.HttpOnly || csrfCookie.SameSite != http.SameSiteStrictMode || !csrfCookie.Secure || csrfCookie.Path != "/" {
		t.Errorf("CSRF cookie attributes = HttpOnly:%v SameSite:%v Secure:%v Path:%q", csrfCookie.HttpOnly, csrfCookie.SameSite, csrfCookie.Secure, csrfCookie.Path)
	}
	credential, present, err := LoadCredential(server.deps.State)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if !present || !credential.Verify("correct horse battery staple") {
		t.Fatal("setup did not persist a working credential")
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(sessionCookie)
	indexResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(indexResponse, request)
	if indexResponse.Code != http.StatusOK {
		t.Fatalf("authenticated GET / status = %d, want %d", indexResponse.Code, http.StatusOK)
	}
}

func TestSetupRejectsShortPassword(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	response := performFormRequest(server, http.MethodPost, "/setup", "password", "short", "192.0.2.1:1234")

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if !strings.Contains(response.Body.String(), "at least") {
		t.Errorf("body = %q, want password-length error", response.Body.String())
	}
	if _, present, err := LoadCredential(server.deps.State); err != nil || present {
		t.Fatalf("credential after rejected setup = present:%v error:%v, want absent", present, err)
	}
}

func TestSetupIsFirstRunOnly(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")

	getResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(getResponse, httptest.NewRequest(http.MethodGet, "/setup", nil))
	assertRedirect(t, getResponse.Result(), "/")

	postResponse := performFormRequest(server, http.MethodPost, "/setup", "password", "another secure password", "192.0.2.1:1234")
	if postResponse.Code != http.StatusConflict {
		t.Fatalf("POST /setup status = %d, want %d", postResponse.Code, http.StatusConflict)
	}
}

func TestConcurrentSetupAllowsOnlyOneCredential(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	const requests = 4
	start := make(chan struct{})
	statuses := make(chan int, requests)
	var wait sync.WaitGroup
	for range requests {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			response := performFormRequest(server, http.MethodPost, "/setup", "password", "correct horse battery staple", "192.0.2.1:1234")
			statuses <- response.Code
		}()
	}
	close(start)
	wait.Wait()
	close(statuses)

	created := 0
	conflicts := 0
	for status := range statuses {
		switch status {
		case http.StatusSeeOther:
			created++
		case http.StatusConflict:
			conflicts++
		default:
			t.Errorf("setup status = %d, want %d or %d", status, http.StatusSeeOther, http.StatusConflict)
		}
	}
	if created != 1 || conflicts != requests-1 {
		t.Errorf("setup results = %d created, %d conflicts; want 1 created, %d conflicts", created, conflicts, requests-1)
	}
}

func TestCredentialWithoutSessionRedirectsToLogin(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	assertRedirect(t, response.Result(), "/login")
}

func TestLoginGoodAndBad(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")

	badResponse := performFormRequest(server, http.MethodPost, "/login", "password", "incorrect password", "192.0.2.1:1234")
	if badResponse.Code != http.StatusUnauthorized {
		t.Fatalf("bad login status = %d, want %d", badResponse.Code, http.StatusUnauthorized)
	}
	if body := badResponse.Body.String(); !strings.Contains(body, "invalid credentials") || strings.Contains(body, "incorrect password") {
		t.Errorf("bad login body = %q, want generic invalid-credentials error", body)
	}

	goodResponse := performFormRequest(server, http.MethodPost, "/login", "password", "correct horse battery staple", "192.0.2.1:1234")
	assertRedirect(t, goodResponse.Result(), "/")
	findResponseCookie(t, goodResponse.Result(), "sr_session")
	findResponseCookie(t, goodResponse.Result(), "sr_csrf")
}

func TestLoginRedirectsToSetupWithoutCredential(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	response := performFormRequest(server, http.MethodPost, "/login", "password", "anything at all", "192.0.2.1:1234")

	assertRedirect(t, response.Result(), "/setup")
}

func TestLoginRateLimitPerIP(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{
		LoginRatePerIP: 0.000001,
		LoginBurst:     1,
	})
	saveTestCredential(t, server, "correct horse battery staple")

	first := performFormRequest(server, http.MethodPost, "/login", "password", "incorrect password", "192.0.2.1:1234")
	if first.Code != http.StatusUnauthorized {
		t.Fatalf("first login status = %d, want %d", first.Code, http.StatusUnauthorized)
	}
	second := performFormRequest(server, http.MethodPost, "/login", "password", "incorrect password", "192.0.2.1:5678")
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second login status = %d, want %d", second.Code, http.StatusTooManyRequests)
	}
}

func TestLoginRateLimitReadsConfigLive(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	cfg := server.deps.Cfg()
	cfg.Admin.LoginRatePerIP = 0.000001
	cfg.Admin.LoginBurst = 1

	first := performFormRequest(server, http.MethodPost, "/login", "password", "incorrect password", "192.0.2.2:1234")
	if first.Code != http.StatusUnauthorized {
		t.Fatalf("first login status = %d, want %d", first.Code, http.StatusUnauthorized)
	}
	second := performFormRequest(server, http.MethodPost, "/login", "password", "incorrect password", "192.0.2.2:5678")
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second login status = %d, want %d", second.Code, http.StatusTooManyRequests)
	}
}

func TestLogoutRequiresCSRFAndClearsAuthCookies(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")

	missingToken := httptest.NewRequest(http.MethodPost, "/logout", nil)
	missingToken.AddCookie(validSessionCookie(t, server))
	missingResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(missingResponse, missingToken)
	if missingResponse.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF status = %d, want %d", missingResponse.Code, http.StatusForbidden)
	}

	request := httptest.NewRequest(http.MethodPost, "/logout", nil)
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "logout-token"})
	request.Header.Set("X-CSRF-Token", "logout-token")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	assertRedirect(t, response.Result(), "/login")
	for _, name := range []string{sessionCookieName, csrfCookieName} {
		cookie := findResponseCookie(t, response.Result(), name)
		if cookie.MaxAge >= 0 {
			t.Errorf("%s cookie MaxAge = %d, want negative", name, cookie.MaxAge)
		}
	}
}

func TestCSRFGate(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	server.mux().HandleFunc("POST /mutate", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	tests := []struct {
		name       string
		csrfCookie string
		csrfHeader string
		wantStatus int
	}{
		{name: "absent", wantStatus: http.StatusForbidden},
		{name: "mismatch", csrfCookie: "cookie-token", csrfHeader: "header-token", wantStatus: http.StatusForbidden},
		{name: "matching", csrfCookie: "matching-token", csrfHeader: "matching-token", wantStatus: http.StatusNoContent},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/mutate", nil)
			request.AddCookie(validSessionCookie(t, server))
			if test.csrfCookie != "" {
				request.AddCookie(&http.Cookie{Name: "sr_csrf", Value: test.csrfCookie})
			}
			if test.csrfHeader != "" {
				request.Header.Set("X-CSRF-Token", test.csrfHeader)
			}
			response := httptest.NewRecorder()

			server.Handler().ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Errorf("status = %d, want %d", response.Code, test.wantStatus)
			}
		})
	}
}

func TestCSRFGateCapsMutationBodies(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	body := `{"config":"` + strings.Repeat("x", 1<<20) + `"}`
	request := httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(body))
	request.AddCookie(validSessionCookie(t, server))
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "matching-token"})
	request.Header.Set("X-CSRF-Token", "matching-token")
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized mutation status = %d, want %d; body = %q", response.Code, http.StatusBadRequest, response.Body.String())
	}
}

func TestPublicRoutesDoNotRequireAuthentication(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	tests := []struct {
		method     string
		path       string
		wantStatus int
	}{
		{method: http.MethodGet, path: "/login", wantStatus: http.StatusOK},
		{method: http.MethodGet, path: "/setup", wantStatus: http.StatusOK},
		{method: http.MethodGet, path: "/assets/app.css", wantStatus: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			response := httptest.NewRecorder()

			server.Handler().ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Errorf("status = %d, want %d", response.Code, test.wantStatus)
			}
		})
	}
}

func TestAuthGateFailsClosedWithoutState(t *testing.T) {
	cfg := &config.Config{Admin: config.AdminConfig{SessionTTL: time.Hour}}
	server, err := New(Deps{Cfg: func() *config.Config { return cfg }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}
}

func performFormRequest(server *Server, method, path, field, value, remoteAddr string) *httptest.ResponseRecorder {
	form := url.Values{}
	if field != "" {
		form.Set(field, value)
	}
	request := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.RemoteAddr = remoteAddr
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func assertRedirect(t *testing.T, response *http.Response, location string) {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusSeeOther)
	}
	if got := response.Header.Get("Location"); got != location {
		t.Errorf("Location = %q, want %q", got, location)
	}
}

func findResponseCookie(t *testing.T, response *http.Response, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	body, _ := io.ReadAll(response.Body)
	t.Fatalf("response cookies = %v, want %q; body = %q", response.Cookies(), name, body)
	return nil
}
