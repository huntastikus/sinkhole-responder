package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/huntastikus/sinkhole-responder/internal/config"
	"github.com/huntastikus/sinkhole-responder/internal/rulepacks"
)

type rulepackAPIFixture struct {
	server      *Server
	configPath  string
	reloadCount *int
}

type rulepacksAPIResponse struct {
	Packs []struct {
		Name        string `json:"name"`
		Title       string `json:"title"`
		Description string `json:"description"`
		RuleCount   int    `json:"rule_count"`
		Enabled     bool   `json:"enabled"`
	} `json:"packs"`
	Mtime string `json:"mtime"`
}

func TestRulepacksAPIListsAvailablePacksAndEnabledState(t *testing.T) {
	fixture := newRulepackAPIFixture(t, "gpt")
	response := performJSONRequest(t, fixture.server, http.MethodGet, "/api/rulepacks", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /api/rulepacks status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}

	var body rulepacksAPIResponse
	decodeJSON(t, response, &body)
	if body.Mtime == "" || body.Mtime == "0" {
		t.Fatalf("mtime = %q, want a non-zero JSON string", body.Mtime)
	}

	wantPacks := rulepacks.Available()
	if len(body.Packs) != len(wantPacks) {
		t.Fatalf("pack count = %d, want %d", len(body.Packs), len(wantPacks))
	}
	found := map[string]bool{}
	for i, want := range wantPacks {
		got := body.Packs[i]
		if got.Name != want.Name || got.Title != want.Title || got.Description != want.Description || got.RuleCount != want.RuleCount {
			t.Errorf("packs[%d] = %+v, want metadata %+v", i, got, want)
		}
		wantEnabled := want.Name == "gpt"
		if got.Enabled != wantEnabled {
			t.Errorf("pack %q enabled = %v, want %v", got.Name, got.Enabled, wantEnabled)
		}
		if got.Name == "recommended" || got.Name == "gpt" {
			found[got.Name] = true
			if got.RuleCount < 1 {
				t.Errorf("pack %q rule_count = %d, want positive count", got.Name, got.RuleCount)
			}
		}
	}
	if !found["recommended"] || !found["gpt"] {
		t.Fatalf("packs found = %v, want recommended and gpt", found)
	}
}

func TestRulepacksAPIReadsEnabledStateAndMtimeFromDisk(t *testing.T) {
	fixture := newRulepackAPIFixture(t)
	diskConfig, err := config.Load(fixture.configPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	diskConfig.Rulepacks.Enabled = []string{"gpt"}
	data, err := config.MarshalConfig(diskConfig)
	if err != nil {
		t.Fatalf("config.MarshalConfig: %v", err)
	}
	if err := os.WriteFile(fixture.configPath, data, 0o600); err != nil {
		t.Fatalf("external config write: %v", err)
	}

	response := performJSONRequest(t, fixture.server, http.MethodGet, "/api/rulepacks", nil)
	var body rulepacksAPIResponse
	decodeJSON(t, response, &body)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	if body.Mtime != configMtimeString(t, fixture.configPath) {
		t.Errorf("mtime = %q, want disk mtime", body.Mtime)
	}
	for _, pack := range body.Packs {
		if pack.Name == "gpt" && !pack.Enabled {
			t.Error("gpt enabled = false, want disk state true")
		}
	}
}

func TestRulepacksAPIToggleEnablePersistsAndReloads(t *testing.T) {
	fixture := newRulepackAPIFixture(t, "recommended", "recommended")
	response := postRulepackToggle(t, fixture, "gpt", true, configMtimeString(t, fixture.configPath))
	if response.Code != http.StatusOK {
		t.Fatalf("POST enable status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}

	var body struct {
		Mtime   string `json:"mtime"`
		Enabled bool   `json:"enabled"`
	}
	decodeJSON(t, response, &body)
	if body.Mtime == "" || !body.Enabled {
		t.Errorf("response = %+v, want non-empty mtime and enabled true", body)
	}
	if *fixture.reloadCount != 1 {
		t.Fatalf("reload count = %d, want 1", *fixture.reloadCount)
	}
	assertEnabledRulepacks(t, fixture.configPath, []string{"recommended", "gpt"})
}

func TestRulepacksAPIToggleDisableRemovesAllOccurrences(t *testing.T) {
	fixture := newRulepackAPIFixture(t, "recommended", "gpt", "recommended", "gpt")
	response := postRulepackToggle(t, fixture, "gpt", false, configMtimeString(t, fixture.configPath))
	if response.Code != http.StatusOK {
		t.Fatalf("POST disable status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}

	var body struct {
		Enabled bool `json:"enabled"`
	}
	decodeJSON(t, response, &body)
	if body.Enabled {
		t.Error("enabled = true, want false")
	}
	if *fixture.reloadCount != 1 {
		t.Fatalf("reload count = %d, want 1", *fixture.reloadCount)
	}
	assertEnabledRulepacks(t, fixture.configPath, []string{"recommended"})
}

func TestRulepacksAPIToggleRejectsUnknownPack(t *testing.T) {
	fixture := newRulepackAPIFixture(t)
	response := postRulepackToggle(t, fixture, "missing", true, configMtimeString(t, fixture.configPath))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("POST unknown status = %d, want %d; body = %s", response.Code, http.StatusBadRequest, response.Body.String())
	}
	assertRulepackError(t, response, `unknown rulepack "missing"`)
	if *fixture.reloadCount != 0 {
		t.Fatalf("reload count = %d, want 0", *fixture.reloadCount)
	}
}

func TestRulepacksAPIToggleRejectsStaleMtime(t *testing.T) {
	fixture := newRulepackAPIFixture(t)
	mtime, err := strconv.ParseInt(configMtimeString(t, fixture.configPath), 10, 64)
	if err != nil {
		t.Fatalf("parse config mtime: %v", err)
	}
	response := postRulepackToggle(t, fixture, "gpt", true, strconv.FormatInt(mtime-1, 10))
	if response.Code != http.StatusConflict {
		t.Fatalf("POST stale mtime status = %d, want %d; body = %s", response.Code, http.StatusConflict, response.Body.String())
	}
	var body struct {
		Error        string `json:"error"`
		CurrentMtime string `json:"current_mtime"`
	}
	decodeJSON(t, response, &body)
	if body.Error != "config file changed on disk since it was loaded; reload before saving" {
		t.Errorf("error = %q, want standard conflict message", body.Error)
	}
	if body.CurrentMtime != configMtimeString(t, fixture.configPath) {
		t.Errorf("current_mtime = %q, want %q", body.CurrentMtime, configMtimeString(t, fixture.configPath))
	}
}

func TestRulepacksAPIToggleRejectsMissingConfigPath(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "test-password")
	fixture := &rulepackAPIFixture{server: server}
	response := postRulepackToggle(t, fixture, "gpt", true, "0")
	if response.Code != http.StatusConflict {
		t.Fatalf("POST without config path status = %d, want %d; body = %s", response.Code, http.StatusConflict, response.Body.String())
	}
	assertRulepackError(t, response, "config file path is not configured; live write-back is unavailable")
}

func TestRulepacksAPIRequiresAuthentication(t *testing.T) {
	fixture := newRulepackAPIFixture(t)
	response := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/rulepacks", nil))
	if response.Code != http.StatusSeeOther {
		t.Fatalf("unauthenticated status = %d, want %d", response.Code, http.StatusSeeOther)
	}
	if location := response.Header().Get("Location"); location != "/login" {
		t.Errorf("Location = %q, want /login", location)
	}
}

func TestRulepacksPageIsEmbeddedAndCSPProtected(t *testing.T) {
	fixture := newRulepackAPIFixture(t)
	response := performJSONRequest(t, fixture.server, http.MethodGet, "/rulepacks", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /rulepacks status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", contentType)
	}
	if !strings.Contains(response.Body.String(), "/assets/rulepacks.js") {
		t.Error("page does not load /assets/rulepacks.js")
	}
	if csp := response.Header().Get("Content-Security-Policy"); csp != contentSecurityPolicy {
		t.Errorf("Content-Security-Policy = %q, want %q", csp, contentSecurityPolicy)
	}
}

func TestRulepackRoutesAreMethodAware(t *testing.T) {
	fixture := newRulepackAPIFixture(t)
	for _, test := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/api/rulepacks"},
		{method: http.MethodGet, path: "/api/rulepacks/toggle"},
	} {
		response := performJSONRequest(t, fixture.server, test.method, test.path, nil)
		if response.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s status = %d, want %d", test.method, test.path, response.Code, http.StatusMethodNotAllowed)
		}
	}
}

func newRulepackAPIFixture(t *testing.T, enabled ...string) *rulepackAPIFixture {
	t.Helper()
	server := newTestServer(t, config.AdminConfig{})
	configPath := server.deps.State.Path("config.yaml")
	cfg, err := config.ParseBytes(nil, filepath.Dir(configPath))
	if err != nil {
		t.Fatalf("config.ParseBytes: %v", err)
	}
	cfg.Rulepacks.Enabled = append([]string(nil), enabled...)
	data, err := config.MarshalConfig(cfg)
	if err != nil {
		t.Fatalf("config.MarshalConfig: %v", err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	reloadCount := 0
	current := cfg
	server.deps.Cfg = func() *config.Config { return current }
	server.deps.ConfigPath = configPath
	server.deps.Reload = func(next *config.Config) error {
		reloadCount++
		current = next
		return nil
	}
	saveTestCredential(t, server, "test-password")
	return &rulepackAPIFixture{server: server, configPath: configPath, reloadCount: &reloadCount}
}

func postRulepackToggle(t *testing.T, fixture *rulepackAPIFixture, name string, enabled bool, mtime string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"name": name, "enabled": enabled, "mtime": mtime})
	if err != nil {
		t.Fatalf("marshal toggle request: %v", err)
	}
	return performJSONRequest(t, fixture.server, http.MethodPost, "/api/rulepacks/toggle", body)
}

func assertRulepackError(t *testing.T, response *httptest.ResponseRecorder, want string) {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	decodeJSON(t, response, &body)
	if body.Error != want {
		t.Errorf("error = %q, want %q", body.Error, want)
	}
}

func assertEnabledRulepacks(t *testing.T, configPath string, want []string) {
	t.Helper()
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if !reflect.DeepEqual(cfg.Rulepacks.Enabled, want) {
		t.Errorf("rulepacks.enabled = %v, want %v", cfg.Rulepacks.Enabled, want)
	}
}

func configMtimeString(t *testing.T, configPath string) string {
	t.Helper()
	file, err := os.Open(configPath)
	if err != nil {
		t.Fatalf("open config: %v", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	return strconv.FormatInt(info.ModTime().UnixNano(), 10)
}
