package admin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/huntastikus/sinkhole-responder/internal/config"
)

func TestDashboardAndAssetsAreServed(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	cookie := validSessionCookie(t, server)

	tests := []struct {
		name        string
		path        string
		contentType string
		contains    []string
		noStore     bool
	}{
		{
			name:        "dashboard shell",
			path:        "/",
			contentType: "text/html",
			contains:    []string{`class="metric-grid"`, `data-metric="requests_total"`, "dashboard.js"},
			noStore:     true,
		},
		{
			name:        "dashboard module",
			path:        "/assets/dashboard.js",
			contentType: "javascript",
			contains:    []string{"export function"},
		},
		{
			name:        "dashboard stylesheet",
			path:        "/assets/app.css",
			contentType: "text/css",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			request.AddCookie(cookie)
			response := httptest.NewRecorder()

			server.Handler().ServeHTTP(response, request)

			result := response.Result()
			defer result.Body.Close()
			if result.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want %d", result.StatusCode, http.StatusOK)
			}
			if got := result.Header.Get("Content-Type"); !strings.Contains(got, test.contentType) {
				t.Errorf("Content-Type = %q, want it to contain %q", got, test.contentType)
			}
			if test.noStore && result.Header.Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", result.Header.Get("Cache-Control"))
			}
			assertSecurityHeaders(t, result)

			body, err := io.ReadAll(result.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			for _, want := range test.contains {
				if !strings.Contains(string(body), want) {
					t.Errorf("body does not contain %q", want)
				}
			}
		})
	}
}
