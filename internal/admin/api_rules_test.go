package admin

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/config"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/state"
)

const rulesAPITestYAML = `listen:
  http:
    - 127.0.0.1:8081
rules:
  - name: first
    path_glob: /first/*
    response:
      status: 200
      body: first-body
  - name: second
    path_glob: /second/*
    response:
      status: 204
`

type rulesAPIResponse struct {
	Rules []map[string]any `json:"rules"`
	Mtime string           `json:"mtime"`
}

type rulesWriteAPIResponse struct {
	Error        string `json:"error"`
	Mtime        string `json:"mtime"`
	CurrentMtime string `json:"current_mtime"`
}

type rulesPreviewAPIResponse struct {
	MatchedRuleName string `json:"matched_rule_name"`
	Kind            string `json:"kind"`
	Status          int    `json:"status"`
	ContentType     string `json:"content_type"`
	BodyPreview     string `json:"body_preview"`
	BodyTruncated   bool   `json:"body_truncated"`
	DelayMS         int64  `json:"delay_ms"`
}

type assetsAPIResponse struct {
	Assets []string `json:"assets"`
}

type rulesAPIFixture struct {
	server      *Server
	configPath  string
	reloadCalls int
	applied     *config.Config
}

func TestRulesAPIReportsCurrentRules(t *testing.T) {
	fixture := newRulesAPIFixture(t)
	response := performJSONRequest(t, fixture.server, http.MethodGet, "/api/rules", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	var body rulesAPIResponse
	decodeJSON(t, response, &body)
	if len(body.Rules) != 2 {
		t.Fatalf("rules = %#v, want two rules", body.Rules)
	}
	first := body.Rules[0]
	if first["name"] != "first" || first["path_glob"] != "/first/*" {
		t.Errorf("first rule = %#v, want name and path_glob", first)
	}
	if _, ok := first["response"].(map[string]any); !ok {
		t.Errorf("first rule response = %#v, want object", first["response"])
	}
	if body.Mtime != strconv.FormatInt(fileMtime(t, fixture.configPath), 10) {
		t.Errorf("mtime = %q, want file mtime", body.Mtime)
	}
}

func TestRulesAPIReadsRulesAndMtimeFromDisk(t *testing.T) {
	fixture := newRulesAPIFixture(t)
	external := strings.Replace(rulesAPITestYAML, "name: first", "name: externally-edited", 1)
	if err := state.WriteFileAtomic(fixture.configPath, []byte(external), 0o600); err != nil {
		t.Fatalf("external config write: %v", err)
	}

	response := performJSONRequest(t, fixture.server, http.MethodGet, "/api/rules", nil)
	var body rulesAPIResponse
	decodeJSON(t, response, &body)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	if body.Rules[0]["name"] != "externally-edited" {
		t.Errorf("first rule name = %#v, want externally-edited", body.Rules[0]["name"])
	}
	if want := strconv.FormatInt(fileMtime(t, fixture.configPath), 10); body.Mtime != want {
		t.Errorf("mtime = %q, want %q", body.Mtime, want)
	}
}

func TestRulesPreviewMatchesCurrentUserRuleThroughSelectionChain(t *testing.T) {
	fixture := newRulesAPIFixture(t)
	request := map[string]any{
		"method": "GET",
		"path":   "/first/ad.js",
		"host":   "pagead2.googlesyndication.com",
		"headers": map[string]string{
			"Sec-Fetch-Dest": "script",
			"Accept":         "*/*",
		},
	}
	response := performJSONRequest(t, fixture.server, http.MethodPost, "/api/rules/preview", marshalRulesAPIRequest(t, request))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	var body rulesPreviewAPIResponse
	decodeJSON(t, response, &body)
	if body.MatchedRuleName != "first" {
		t.Errorf("matched rule name = %q, want first", body.MatchedRuleName)
	}
	if body.Kind != "script" || body.Status != http.StatusOK || body.ContentType != "application/javascript" {
		t.Errorf("decision = kind %q, status %d, content type %q; want script, 200, application/javascript", body.Kind, body.Status, body.ContentType)
	}
	if body.BodyPreview != "first-body" || body.BodyTruncated || body.DelayMS != 0 {
		t.Errorf("preview = body %q, truncated %t, delay %d; want first-body, false, 0", body.BodyPreview, body.BodyTruncated, body.DelayMS)
	}
}

func TestRulesPreviewReturnsGenericDecisionWhenNoRuleMatches(t *testing.T) {
	fixture := newRulesAPIFixture(t)
	request := map[string]any{
		"path": "/unmatched.css",
		"headers": map[string]string{
			"Accept": "text/css",
		},
	}
	response := performJSONRequest(t, fixture.server, http.MethodPost, "/api/rules/preview", marshalRulesAPIRequest(t, request))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	var body rulesPreviewAPIResponse
	decodeJSON(t, response, &body)
	if body.MatchedRuleName != "" {
		t.Errorf("matched rule name = %q, want empty", body.MatchedRuleName)
	}
	if body.Status != fixture.server.deps.Cfg().Defaults.Status {
		t.Errorf("status = %d, want generic default %d", body.Status, fixture.server.deps.Cfg().Defaults.Status)
	}
	if body.Kind != "style" || body.ContentType != "text/css" {
		t.Errorf("decision = kind %q, content type %q; want style, text/css", body.Kind, body.ContentType)
	}
}

func TestRulesPreviewIncludesEnabledRulepacks(t *testing.T) {
	fixture := newRulesAPIFixture(t)
	fixture.server.deps.Cfg().Rulepacks.Enabled = []string{"recommended"}
	request := map[string]any{
		"method": "GET",
		"path":   "/tag/js/gpt.js",
		"host":   "securepubads.g.doubleclick.net",
	}
	response := performJSONRequest(t, fixture.server, http.MethodPost, "/api/rules/preview", marshalRulesAPIRequest(t, request))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	var body rulesPreviewAPIResponse
	decodeJSON(t, response, &body)
	if body.MatchedRuleName != "gpt-securepubads-tag" {
		t.Errorf("matched rule name = %q, want gpt-securepubads-tag", body.MatchedRuleName)
	}
	if body.ContentType != "application/javascript" {
		t.Errorf("content type = %q, want application/javascript", body.ContentType)
	}
}

func TestAssetsAPIReportsSortedEmbeddedAssetNames(t *testing.T) {
	fixture := newRulesAPIFixture(t)
	response := performJSONRequest(t, fixture.server, http.MethodGet, "/api/assets", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	var body assetsAPIResponse
	decodeJSON(t, response, &body)
	for _, name := range []string{"empty-js", "stub-adsense"} {
		if !slices.Contains(body.Assets, name) {
			t.Errorf("assets = %#v, want %q", body.Assets, name)
		}
	}
	if !slices.IsSorted(body.Assets) {
		t.Errorf("assets = %#v, want sorted names", body.Assets)
	}
}

func TestRulesAPIAppliesValidRules(t *testing.T) {
	fixture := newRulesAPIFixture(t)
	request := map[string]any{
		"rules": []map[string]any{{
			"name":      "replacement",
			"path_glob": "/replacement/*",
			"response": map[string]any{
				"status": 200,
				"body":   "new-body",
			},
		}},
		"mtime": strconv.FormatInt(fileMtime(t, fixture.configPath), 10),
	}
	response := performJSONRequest(t, fixture.server, http.MethodPut, "/api/rules", marshalRulesAPIRequest(t, request))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	var body rulesWriteAPIResponse
	decodeJSON(t, response, &body)
	if want := strconv.FormatInt(fileMtime(t, fixture.configPath), 10); body.Mtime == "0" || body.Mtime != want {
		t.Errorf("mtime = %q, want new file mtime %q", body.Mtime, want)
	}
	written, err := config.Load(fixture.configPath)
	if err != nil {
		t.Fatalf("load written config: %v", err)
	}
	if len(written.Rules) != 1 || written.Rules[0].Name != "replacement" || written.Rules[0].Response.Body != "new-body" {
		t.Errorf("written rules = %#v, want replacement rule with new body", written.Rules)
	}
	if fixture.reloadCalls != 1 {
		t.Fatalf("reload calls = %d, want 1", fixture.reloadCalls)
	}
	if fixture.applied == nil || len(fixture.applied.Rules) != 1 || fixture.applied.Rules[0].Name != "replacement" {
		t.Fatalf("applied config = %#v, want replacement rule", fixture.applied)
	}
}

func TestRulesAPIRejectsStaleMtime(t *testing.T) {
	fixture := newRulesAPIFixture(t)
	original := readRulesConfigFile(t, fixture.configPath)
	mtime := fileMtime(t, fixture.configPath)
	request := map[string]any{
		"rules": []map[string]any{{"name": "replacement", "path_glob": "/replacement/*"}},
		"mtime": mtime - 1,
	}
	response := performJSONRequest(t, fixture.server, http.MethodPut, "/api/rules", marshalRulesAPIRequest(t, request))

	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusConflict, response.Body.String())
	}
	var body rulesWriteAPIResponse
	decodeJSON(t, response, &body)
	if body.CurrentMtime != strconv.FormatInt(mtime, 10) || body.Error != "config file changed on disk since it was loaded; reload before saving" {
		t.Errorf("response = %#v, want current mtime %d and stale-file error", body, mtime)
	}
	assertConfigFileBytes(t, fixture.configPath, original)
	if fixture.reloadCalls != 0 {
		t.Errorf("reload calls = %d, want 0", fixture.reloadCalls)
	}
}

func TestRulesAPIRejectsInvalidRule(t *testing.T) {
	fixture := newRulesAPIFixture(t)
	original := readRulesConfigFile(t, fixture.configPath)
	request := map[string]any{
		"rules": []map[string]any{{
			"name":          "invalid",
			"path_glob":     "/invalid/*",
			"unknown_field": true,
		}},
		"mtime": strconv.FormatInt(fileMtime(t, fixture.configPath), 10),
	}
	response := performJSONRequest(t, fixture.server, http.MethodPut, "/api/rules", marshalRulesAPIRequest(t, request))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusBadRequest, response.Body.String())
	}
	var body rulesWriteAPIResponse
	decodeJSON(t, response, &body)
	if !strings.Contains(body.Error, "field unknown_field not found") {
		t.Errorf("error = %q, want yaml.v3 unknown-field detail", body.Error)
	}
	assertConfigFileBytes(t, fixture.configPath, original)
	if fixture.reloadCalls != 0 {
		t.Errorf("reload calls = %d, want 0", fixture.reloadCalls)
	}
}

func TestRulesAPIReordersRules(t *testing.T) {
	fixture := newRulesAPIFixture(t)
	request := map[string]any{
		"order": []int{1, 0},
		"mtime": fileMtime(t, fixture.configPath),
	}
	response := performJSONRequest(t, fixture.server, http.MethodPost, "/api/rules/reorder", marshalRulesAPIRequest(t, request))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	written, err := config.Load(fixture.configPath)
	if err != nil {
		t.Fatalf("load written config: %v", err)
	}
	if len(written.Rules) != 2 || written.Rules[0].Name != "second" || written.Rules[1].Name != "first" {
		t.Errorf("written rule names = %#v, want [second first]", written.Rules)
	}
	if fixture.reloadCalls != 1 {
		t.Errorf("reload calls = %d, want 1", fixture.reloadCalls)
	}
}

func TestRulesAPIRejectsInvalidReorder(t *testing.T) {
	tests := []struct {
		name  string
		order []int
	}{
		{name: "wrong length", order: []int{0}},
		{name: "duplicate", order: []int{0, 0}},
		{name: "out of range", order: []int{0, 2}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRulesAPIFixture(t)
			original := readRulesConfigFile(t, fixture.configPath)
			request := map[string]any{
				"order": test.order,
				"mtime": fileMtime(t, fixture.configPath),
			}
			response := performJSONRequest(t, fixture.server, http.MethodPost, "/api/rules/reorder", marshalRulesAPIRequest(t, request))

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusBadRequest, response.Body.String())
			}
			var body rulesWriteAPIResponse
			decodeJSON(t, response, &body)
			if body.Error != "order must be a permutation of the current rule indices" {
				t.Errorf("error = %q, want permutation error", body.Error)
			}
			assertConfigFileBytes(t, fixture.configPath, original)
			if fixture.reloadCalls != 0 {
				t.Errorf("reload calls = %d, want 0", fixture.reloadCalls)
			}
		})
	}
}

func TestRulesAPIRequiresAuthentication(t *testing.T) {
	fixture := newRulesAPIFixture(t)
	response := httptest.NewRecorder()

	fixture.server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/rules", nil))

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
		t.Errorf("status/location = %d/%q, want %d/%q", response.Code, response.Header().Get("Location"), http.StatusSeeOther, "/login")
	}
}

func TestRulesPreviewRequiresAuthentication(t *testing.T) {
	fixture := newRulesAPIFixture(t)
	response := httptest.NewRecorder()

	fixture.server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/rules/preview", strings.NewReader(`{"path":"/first/ad.js"}`)))

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
		t.Errorf("status/location = %d/%q, want %d/%q", response.Code, response.Header().Get("Location"), http.StatusSeeOther, "/login")
	}
}

func TestRulesPageServesBuilderWithSecurityHeaders(t *testing.T) {
	fixture := newRulesAPIFixture(t)
	response := performJSONRequest(t, fixture.server, http.MethodGet, "/rules", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", got)
	}
	if body := response.Body.String(); !strings.Contains(body, "rules.js") {
		t.Errorf("body does not contain rules.js: %q", body)
	}
	assertSecurityHeaders(t, response.Result())
}

func TestRulesAPIsRejectOtherMethods(t *testing.T) {
	fixture := newRulesAPIFixture(t)
	for _, test := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/api/rules"},
		{method: http.MethodGet, path: "/api/rules/reorder"},
		{method: http.MethodGet, path: "/api/rules/preview"},
		{method: http.MethodPost, path: "/api/assets"},
	} {
		response := performJSONRequest(t, fixture.server, test.method, test.path, nil)
		if response.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s status = %d, want %d", test.method, test.path, response.Code, http.StatusMethodNotAllowed)
		}
	}
}

func newRulesAPIFixture(t *testing.T) *rulesAPIFixture {
	t.Helper()
	d, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	configPath := d.Path("config.yaml")
	if err := os.WriteFile(configPath, []byte(rulesAPITestYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	fixture := &rulesAPIFixture{configPath: configPath}
	current := cfg
	fixture.server, err = New(Deps{
		Cfg:        func() *config.Config { return current },
		ConfigPath: configPath,
		Reload: func(applied *config.Config) error {
			fixture.reloadCalls++
			fixture.applied = applied
			current = applied
			return nil
		},
		State:  d,
		Logger: logger,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	saveTestCredential(t, fixture.server, "correct horse battery staple")
	return fixture
}

func marshalRulesAPIRequest(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return data
}

func readRulesConfigFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	return data
}
