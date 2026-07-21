package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/huntastikus/sinkhole-responder/internal/config"
	"github.com/huntastikus/sinkhole-responder/internal/rules"
)

type toolsTestDomainResponse struct {
	MatchedRuleName string `json:"matched_rule_name"`
	Kind            string `json:"kind"`
	Status          int    `json:"status"`
	ContentType     string `json:"content_type"`
	BodyPreview     string `json:"body_preview"`
	BodyTruncated   bool   `json:"body_truncated"`
	WouldBlock      bool   `json:"would_block"`
}

type toolsAGHConfigResponse struct {
	IP      string   `json:"ip"`
	Steps   []string `json:"steps"`
	YAML    string   `json:"yaml"`
	Warning string   `json:"warning"`
}

func TestToolsTestDomainUsesMergedSelectionChain(t *testing.T) {
	server := newToolsTestServer(t)
	requestBody := marshalToolsRequest(t, map[string]string{
		"domain": "pagead2.googlesyndication.com",
		"path":   "/pagead/js/adsbygoogle.js",
		"method": http.MethodGet,
	})
	response := performJSONRequest(t, server, http.MethodPost, "/api/tools/test-domain", requestBody)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	var body toolsTestDomainResponse
	decodeJSON(t, response, &body)
	if body.MatchedRuleName != "known-adsense" {
		t.Errorf("matched rule name = %q, want known-adsense", body.MatchedRuleName)
	}
	if body.Kind != "script" || body.Status != http.StatusOK || body.ContentType != "application/javascript" {
		t.Errorf("decision = kind %q, status %d, content type %q; want script, 200, application/javascript", body.Kind, body.Status, body.ContentType)
	}
	if len(body.BodyPreview) != rulesPreviewBodyLimit || !body.BodyTruncated {
		t.Errorf("preview length/truncated = %d/%t, want %d/true", len(body.BodyPreview), body.BodyTruncated, rulesPreviewBodyLimit)
	}
	if !body.WouldBlock {
		t.Error("would_block = false, want true")
	}
}

func TestToolsTestDomainReturnsGenericDecisionWhenNoRuleMatches(t *testing.T) {
	server := newToolsTestServer(t)
	requestBody := marshalToolsRequest(t, map[string]string{
		"domain": "unmatched.example",
		"path":   "/styles/unmatched.css",
	})
	response := performJSONRequest(t, server, http.MethodPost, "/api/tools/test-domain", requestBody)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	var body toolsTestDomainResponse
	decodeJSON(t, response, &body)
	if body.MatchedRuleName != "" {
		t.Errorf("matched rule name = %q, want empty", body.MatchedRuleName)
	}
	if body.Kind != "style" || body.ContentType != "text/css" {
		t.Errorf("generic decision = kind %q, content type %q; want style, text/css", body.Kind, body.ContentType)
	}
	if !body.WouldBlock {
		t.Error("would_block = false, want true for the responder's generic placeholder")
	}
}

func TestToolsAGHConfigForIPv4(t *testing.T) {
	server := newToolsTestServer(t)
	response := performJSONRequest(t, server, http.MethodGet, "/api/tools/agh-config?ip=192.168.1.10", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	var body toolsAGHConfigResponse
	decodeJSON(t, response, &body)
	if body.IP != "192.168.1.10" {
		t.Errorf("ip = %q, want 192.168.1.10", body.IP)
	}
	if len(body.Steps) == 0 {
		t.Error("steps are empty")
	}
	for _, want := range []string{"blocking_mode: custom_ip", "blocking_ipv4: 192.168.1.10", "blocking_ipv6: \"\""} {
		if !strings.Contains(body.YAML, want) {
			t.Errorf("yaml %q does not contain %q", body.YAML, want)
		}
	}
	if body.Warning == "" {
		t.Error("warning is empty")
	}
}

func TestToolsAGHConfigForIPv6(t *testing.T) {
	server := newToolsTestServer(t)
	response := performJSONRequest(t, server, http.MethodGet, "/api/tools/agh-config?ip=2001%3Adb8%3A%3A10", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	var body toolsAGHConfigResponse
	decodeJSON(t, response, &body)
	if body.IP != "2001:db8::10" {
		t.Errorf("ip = %q, want 2001:db8::10", body.IP)
	}
	for _, want := range []string{"blocking_ipv4: \"\"", "blocking_ipv6: 2001:db8::10"} {
		if !strings.Contains(body.YAML, want) {
			t.Errorf("yaml %q does not contain %q", body.YAML, want)
		}
	}
}

func TestToolsAGHConfigRejectsInvalidIP(t *testing.T) {
	server := newToolsTestServer(t)
	response := performJSONRequest(t, server, http.MethodGet, "/api/tools/agh-config?ip=nope", nil)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusBadRequest, response.Body.String())
	}
	var body map[string]string
	decodeJSON(t, response, &body)
	if body["error"] != "invalid ip" {
		t.Errorf("error = %q, want invalid ip", body["error"])
	}
}

func TestToolsPageIsEmbeddedAndCSPProtected(t *testing.T) {
	server := newToolsTestServer(t)
	response := performJSONRequest(t, server, http.MethodGet, "/tools", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", contentType)
	}
	if !strings.Contains(response.Body.String(), "/assets/tools.js") {
		t.Errorf("page does not load /assets/tools.js: %q", response.Body.String())
	}
	if csp := response.Header().Get("Content-Security-Policy"); csp != contentSecurityPolicy {
		t.Errorf("Content-Security-Policy = %q, want %q", csp, contentSecurityPolicy)
	}
}

func TestToolsTestDomainRequiresAuthentication(t *testing.T) {
	server := newToolsTestServer(t)
	request := httptest.NewRequest(http.MethodPost, "/api/tools/test-domain", strings.NewReader(`{"domain":"example.com"}`))
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
		t.Errorf("status/location = %d/%q, want %d/%q", response.Code, response.Header().Get("Location"), http.StatusSeeOther, "/login")
	}
}

func TestToolsRoutesRejectOtherMethods(t *testing.T) {
	server := newToolsTestServer(t)
	for _, test := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/api/tools/test-domain"},
		{method: http.MethodPost, path: "/api/tools/agh-config?ip=192.168.1.10"},
		{method: http.MethodPost, path: "/tools"},
	} {
		response := performJSONRequest(t, server, test.method, test.path, nil)
		if response.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s status = %d, want %d", test.method, test.path, response.Code, http.StatusMethodNotAllowed)
		}
	}
}

func newToolsTestServer(t *testing.T) *Server {
	t.Helper()
	server := newTestServer(t, config.AdminConfig{})
	cfg := server.deps.Cfg()
	cfg.Rules = []rules.Rule{{
		Name:     "known-adsense",
		Host:     "pagead2.googlesyndication.com",
		PathGlob: "/pagead/js/*",
		Method:   http.MethodGet,
		Response: rules.Response{
			Status:      http.StatusOK,
			ContentType: "application/javascript",
			Body:        strings.Repeat("x", rulesPreviewBodyLimit+64),
		},
	}}
	cfg.Rulepacks.Enabled = []string{"recommended"}
	saveTestCredential(t, server, "correct horse battery staple")
	return server
}

func marshalToolsRequest(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return data
}
