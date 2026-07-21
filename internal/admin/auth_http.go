package admin

import (
	"bytes"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

const (
	sessionCookieName = "sr_session"
	csrfCookieName    = "sr_csrf"
)

type authPageData struct {
	Error string
}

func (s *Server) authGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if s.deps.State == nil {
			s.internalError(w, "load admin credential", fmt.Errorf("state directory is nil"))
			return
		}

		if !s.credentialFound.Load() {
			_, present, err := s.loadCredential()
			if err != nil {
				s.internalError(w, "load admin credential", err)
				return
			}
			if !present {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
				return
			}
		}
		if len(s.sessionKey) == 0 {
			s.internalError(w, "validate admin session", fmt.Errorf("session key is unavailable"))
			return
		}

		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if _, valid := ParseSession(s.sessionKey, cookie.Value); !valid {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) csrfGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isCSRFExemptPath(r.URL.Path) || !isStateChangingMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

		cookie, err := r.Cookie(csrfCookieName)
		if err != nil || !CSRFMatch(cookie.Value, r.Header.Get("X-CSRF-Token")) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isPublicPath(path string) bool {
	return path == "/login" || path == "/logout" || path == "/setup" || strings.HasPrefix(path, "/assets/")
}

func isCSRFExemptPath(path string) bool {
	return path == "/login" || path == "/setup" || strings.HasPrefix(path, "/assets/")
}

func isStateChangingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func (s *Server) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	_, present, err := s.loadCredential()
	if err != nil {
		s.internalError(w, "load admin credential", err)
		return
	}
	if present {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.renderAuthPage(w, "setup.html", authPageData{}, http.StatusOK)
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()

	_, present, err := s.loadCredential()
	if err != nil {
		s.internalError(w, "load admin credential", err)
		return
	}
	if present {
		http.Error(w, http.StatusText(http.StatusConflict), http.StatusConflict)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderAuthPage(w, "setup.html", authPageData{Error: "invalid form submission"}, http.StatusBadRequest)
		return
	}
	credential, err := HashPassword(r.FormValue("password"))
	if err != nil {
		s.renderAuthPage(w, "setup.html", authPageData{Error: err.Error()}, http.StatusBadRequest)
		return
	}
	if err := SaveCredential(s.deps.State, credential); err != nil {
		s.internalError(w, "save admin credential", err)
		return
	}
	s.credentialFound.Store(true)
	if !s.issueAuthCookies(w) {
		return
	}
	http.Redirect(w, r, "/wizard", http.StatusSeeOther)
}

func (s *Server) handleLoginPage(w http.ResponseWriter, _ *http.Request) {
	s.renderAuthPage(w, "login.html", authPageData{}, http.StatusOK)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.allowLogin(r.RemoteAddr) {
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return
	}
	credential, present, err := s.loadCredential()
	if err != nil {
		s.internalError(w, "load admin credential", err)
		return
	}
	if !present {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil || !credential.Verify(r.FormValue("password")) {
		s.renderAuthPage(w, "login.html", authPageData{Error: "invalid credentials"}, http.StatusUnauthorized)
		return
	}
	if !s.issueAuthCookies(w) {
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Pin cookie Secure to the admin TLS state bound at startup, not the live
	// config: an admin-TLS change is restart-pending, so the plane is still
	// served over the startup scheme until the operator restarts.
	secure := s.adminTLSActive
	for _, cookie := range []*http.Cookie{{
		Name:     sessionCookieName,
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}, {
		Name:     csrfCookieName,
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}} {
		http.SetCookie(w, cookie)
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) issueAuthCookies(w http.ResponseWriter) bool {
	cfg := s.deps.Cfg()
	if len(s.sessionKey) == 0 {
		s.internalError(w, "issue admin session", fmt.Errorf("session key is unavailable"))
		return false
	}

	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName,
		Value: SignSession(s.sessionKey, Session{
			User: "admin",
			Exp:  time.Now().Add(cfg.Admin.SessionTTL),
		}),
		Path:     "/",
		HttpOnly: true,
		Secure:   s.adminTLSActive,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    NewCSRFToken(),
		Path:     "/",
		Secure:   s.adminTLSActive,
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

func (s *Server) loadCredential() (Credential, bool, error) {
	if s.deps.State == nil {
		return Credential{}, false, fmt.Errorf("state directory is nil")
	}
	credential, present, err := LoadCredential(s.deps.State)
	if err == nil && present {
		// Once credentials exist, deleting the file requires a restart to re-enter setup.
		s.credentialFound.Store(true)
	}
	return credential, present, err
}

func (s *Server) allowLogin(remoteAddr string) bool {
	cfg := s.deps.Cfg()
	loginRate := rate.Limit(cfg.Admin.LoginRatePerIP)
	if loginRate <= 0 {
		return true
	}
	loginBurst := cfg.Admin.LoginBurst
	ip := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		ip = host
	}

	s.loginLimitersMu.Lock()
	limiter := s.loginLimiters[ip]
	if limiter == nil {
		// Bound memory from spoofed source addresses; resetting throttles is acceptable.
		if len(s.loginLimiters) > 10000 {
			clear(s.loginLimiters)
		}
		limiter = rate.NewLimiter(loginRate, loginBurst)
		s.loginLimiters[ip] = limiter
	} else {
		limiter.SetLimit(loginRate)
		limiter.SetBurst(loginBurst)
	}
	s.loginLimitersMu.Unlock()
	return limiter.Allow()
}

func (s *Server) renderAuthPage(w http.ResponseWriter, name string, data authPageData, status int) {
	tmpl, err := template.ParseFS(s.web, name)
	if err != nil {
		s.internalError(w, "parse embedded admin page", err)
		return
	}
	var body bytes.Buffer
	if err := tmpl.ExecuteTemplate(&body, name, data); err != nil {
		s.internalError(w, "render embedded admin page", err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body.Bytes())
}

func (s *Server) internalError(w http.ResponseWriter, action string, err error) {
	s.logger.Error(action, "error", err)
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}
