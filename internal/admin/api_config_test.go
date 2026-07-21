package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/config"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/state"
)

const configAPITestYAML = `listen:
  http:
    - 127.0.0.1:8081
logging:
  level: info
`

type configAPIResponse struct {
	Config map[string]any `json:"config"`
	Mtime  string         `json:"mtime"`
	Path   string         `json:"path"`
}

type rawConfigAPIResponse struct {
	Raw   string `json:"raw"`
	Mtime string `json:"mtime"`
	Path  string `json:"path"`
}

type configWriteAPIResponse struct {
	Error        string `json:"error"`
	Mtime        string `json:"mtime"`
	CurrentMtime string `json:"current_mtime"`
}

type configAPIFixture struct {
	server      *Server
	configPath  string
	reloadCalls int
	applied     *config.Config
}

func TestJSONInt64RoundTrip(t *testing.T) {
	const want int64 = 1750000000000000123

	encoded, err := json.Marshal(jsonInt64(want))
	if err != nil {
		t.Fatalf("marshal jsonInt64: %v", err)
	}
	if got := string(encoded); got != `"1750000000000000123"` {
		t.Fatalf("marshaled jsonInt64 = %s, want quoted decimal string", got)
	}

	for _, input := range []string{`"1750000000000000123"`, `1750000000000000123`} {
		var got jsonInt64
		if err := json.Unmarshal([]byte(input), &got); err != nil {
			t.Fatalf("unmarshal jsonInt64 from %s: %v", input, err)
		}
		if int64(got) != want {
			t.Errorf("jsonInt64 from %s = %d, want %d", input, got, want)
		}
	}
}

func TestConfigAPIReportsCurrentConfig(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	response := performJSONRequest(t, fixture.server, http.MethodGet, "/api/config", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var body configAPIResponse
	decodeJSON(t, response, &body)
	listen, ok := body.Config["listen"].(map[string]any)
	if !ok {
		t.Fatalf("config.listen = %#v, want object", body.Config["listen"])
	}
	httpListeners, ok := listen["http"].([]any)
	if !ok || len(httpListeners) != 1 || httpListeners[0] != "127.0.0.1:8081" {
		t.Errorf("config.listen.http = %#v, want [127.0.0.1:8081]", listen["http"])
	}
	logging, ok := body.Config["logging"].(map[string]any)
	if !ok || logging["level"] != "info" {
		t.Errorf("config.logging = %#v, want level info", body.Config["logging"])
	}
	if body.Path != fixture.configPath {
		t.Errorf("path = %q, want %q", body.Path, fixture.configPath)
	}
	if want := strconv.FormatInt(fileMtime(t, fixture.configPath), 10); body.Mtime != want {
		t.Errorf("mtime = %q, want %q", body.Mtime, want)
	}
}

func TestConfigAPIUsesSelfConsistentDiskViewAndRejectsPreEditMtime(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	initialResponse := performJSONRequest(t, fixture.server, http.MethodGet, "/api/config", nil)
	var initial configAPIResponse
	decodeJSON(t, initialResponse, &initial)

	external := strings.Replace(configAPITestYAML, "level: info", "level: debug", 1)
	if err := state.WriteFileAtomic(fixture.configPath, []byte(external), 0o600); err != nil {
		t.Fatalf("external config write: %v", err)
	}
	diskMtime := strconv.FormatInt(fileMtime(t, fixture.configPath), 10)
	if diskMtime == initial.Mtime {
		t.Fatal("external config write did not change mtime")
	}

	getResponse := performJSONRequest(t, fixture.server, http.MethodGet, "/api/config", nil)
	var current configAPIResponse
	decodeJSON(t, getResponse, &current)
	logging := current.Config["logging"].(map[string]any)
	if logging["level"] != "debug" || current.Mtime != diskMtime {
		t.Fatalf("GET disk view = level %#v, mtime %q; want debug and %q", logging["level"], current.Mtime, diskMtime)
	}

	putResponse := performJSONRequest(t, fixture.server, http.MethodPut, "/api/config", structuredWriteRequest(t, current.Config, initial.Mtime))
	if putResponse.Code != http.StatusConflict {
		t.Fatalf("PUT with pre-edit mtime status = %d, want %d; body = %q", putResponse.Code, http.StatusConflict, putResponse.Body.String())
	}
	var conflict configWriteAPIResponse
	decodeJSON(t, putResponse, &conflict)
	if conflict.CurrentMtime != diskMtime {
		t.Errorf("current_mtime = %q, want %q", conflict.CurrentMtime, diskMtime)
	}
}

func TestConfigAPIReturnsErrorForExternallyCorruptedFile(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	if err := state.WriteFileAtomic(fixture.configPath, []byte("unknown_setting: true\n"), 0o600); err != nil {
		t.Fatalf("external config write: %v", err)
	}

	response := performJSONRequest(t, fixture.server, http.MethodGet, "/api/config", nil)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusInternalServerError, response.Body.String())
	}
	var body configWriteAPIResponse
	decodeJSON(t, response, &body)
	if !strings.Contains(body.Error, "parse config file") || !strings.Contains(body.Error, "unknown_setting") {
		t.Errorf("error = %q, want clear parse error", body.Error)
	}
}

func TestConfigAPIAppliesStructuredConfig(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	getResponse := performJSONRequest(t, fixture.server, http.MethodGet, "/api/config", nil)
	var current configAPIResponse
	decodeJSON(t, getResponse, &current)
	current.Config["logging"].(map[string]any)["level"] = "debug"

	response := performJSONRequest(t, fixture.server, http.MethodPut, "/api/config", structuredWriteRequest(t, current.Config, current.Mtime))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	var body configWriteAPIResponse
	decodeJSON(t, response, &body)
	if want := strconv.FormatInt(fileMtime(t, fixture.configPath), 10); body.Mtime == "0" || body.Mtime == current.Mtime || body.Mtime != want {
		t.Errorf("mtime = %q, want new file mtime %q", body.Mtime, want)
	}
	written, err := os.ReadFile(fixture.configPath)
	if err != nil {
		t.Fatalf("read written config: %v", err)
	}
	if !bytes.Contains(written, []byte("level: debug")) {
		t.Errorf("written config = %q, want logging level debug", written)
	}
	if fixture.reloadCalls != 1 {
		t.Fatalf("reload calls = %d, want 1", fixture.reloadCalls)
	}
	if fixture.applied == nil || fixture.applied.Logging.Level != "debug" {
		t.Fatalf("applied config = %#v, want logging level debug", fixture.applied)
	}
}

func TestConfigAPIRejectsStructuredConfigWithStaleMtime(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	original, err := os.ReadFile(fixture.configPath)
	if err != nil {
		t.Fatalf("read original config: %v", err)
	}
	getResponse := performJSONRequest(t, fixture.server, http.MethodGet, "/api/config", nil)
	var current configAPIResponse
	decodeJSON(t, getResponse, &current)

	response := performJSONRequest(t, fixture.server, http.MethodPut, "/api/config", structuredWriteRequest(t, current.Config, mustParseMtime(t, current.Mtime)-1))

	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusConflict, response.Body.String())
	}
	var body configWriteAPIResponse
	decodeJSON(t, response, &body)
	if body.CurrentMtime != current.Mtime || !strings.Contains(body.Error, "changed on disk") {
		t.Errorf("response = %#v, want current mtime %s and changed-on-disk error", body, current.Mtime)
	}
	assertConfigFileBytes(t, fixture.configPath, original)
	if fixture.reloadCalls != 0 {
		t.Errorf("reload calls = %d, want 0", fixture.reloadCalls)
	}
}

func TestConfigAPIRejectsInvalidStructuredConfig(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	original, err := os.ReadFile(fixture.configPath)
	if err != nil {
		t.Fatalf("read original config: %v", err)
	}
	getResponse := performJSONRequest(t, fixture.server, http.MethodGet, "/api/config", nil)
	var current configAPIResponse
	decodeJSON(t, getResponse, &current)
	current.Config["unknown_setting"] = true

	response := performJSONRequest(t, fixture.server, http.MethodPut, "/api/config", structuredWriteRequest(t, current.Config, current.Mtime))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusBadRequest, response.Body.String())
	}
	var body configWriteAPIResponse
	decodeJSON(t, response, &body)
	if !strings.Contains(body.Error, "unknown_setting") {
		t.Errorf("error = %q, want unknown-field detail", body.Error)
	}
	assertConfigFileBytes(t, fixture.configPath, original)
	if fixture.reloadCalls != 0 {
		t.Errorf("reload calls = %d, want 0", fixture.reloadCalls)
	}
}

func TestConfigAPIRejectsStructuredWriteWithoutConfigPath(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	response := performJSONRequest(t, server, http.MethodPut, "/api/config", structuredWriteRequest(t, map[string]any{}, 0))

	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusConflict, response.Body.String())
	}
	var body configWriteAPIResponse
	decodeJSON(t, response, &body)
	const want = "config file path is not configured; live write-back is unavailable"
	if body.Error != want {
		t.Errorf("error = %q, want %q", body.Error, want)
	}
}

func TestConfigAPIRoundTripsDurationStrings(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	getResponse := performJSONRequest(t, fixture.server, http.MethodGet, "/api/config", nil)
	var current configAPIResponse
	decodeJSON(t, getResponse, &current)
	limits := current.Config["limits"].(map[string]any)
	if got, ok := limits["read_timeout"].(string); !ok || got == "" {
		t.Fatalf("config.limits.read_timeout = %#v, want duration string", limits["read_timeout"])
	}

	response := performJSONRequest(t, fixture.server, http.MethodPut, "/api/config", structuredWriteRequest(t, current.Config, current.Mtime))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	if fixture.reloadCalls != 1 {
		t.Errorf("reload calls = %d, want 1", fixture.reloadCalls)
	}
}

func TestConfigPageRequiresAuthentication(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	response := httptest.NewRecorder()

	fixture.server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config", nil))

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
		t.Errorf("status/location = %d/%q, want %d/%q", response.Code, response.Header().Get("Location"), http.StatusSeeOther, "/login")
	}
}

func TestConfigPageServesFormWithSecurityHeaders(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	response := performJSONRequest(t, fixture.server, http.MethodGet, "/config", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", got)
	}
	if body := response.Body.String(); !strings.Contains(body, "config.js") || !strings.Contains(body, "config-form") {
		t.Errorf("body does not contain config.js and config form: %q", body)
	}
	assertSecurityHeaders(t, response.Result())
}

func TestRawConfigAPIReadsConfigFile(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	response := performJSONRequest(t, fixture.server, http.MethodGet, "/api/config/raw", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	var body rawConfigAPIResponse
	decodeJSON(t, response, &body)
	if !strings.Contains(body.Raw, "listen:") {
		t.Errorf("raw = %q, want YAML containing listen:", body.Raw)
	}
	if body.Mtime != strconv.FormatInt(fileMtime(t, fixture.configPath), 10) {
		t.Errorf("mtime = %q, want file mtime", body.Mtime)
	}
	if body.Path != fixture.configPath {
		t.Errorf("path = %q, want %q", body.Path, fixture.configPath)
	}
}

func TestRawConfigAPIFallsBackToMarshaledConfigWithoutPath(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	response := performJSONRequest(t, server, http.MethodGet, "/api/config/raw", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	var body rawConfigAPIResponse
	decodeJSON(t, response, &body)
	if !strings.Contains(body.Raw, "listen:") {
		t.Errorf("raw = %q, want marshaled YAML containing listen:", body.Raw)
	}
	if body.Mtime != "0" || body.Path != "" {
		t.Errorf("mtime/path = %q/%q, want 0/empty", body.Mtime, body.Path)
	}
}

func TestRawConfigAPIAppliesValidConfig(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	beforeMtime := fileMtime(t, fixture.configPath)
	modified := strings.Replace(configAPITestYAML, "level: info", "level: debug", 1)
	response := performJSONRequest(t, fixture.server, http.MethodPut, "/api/config/raw", rawWriteRequest(t, modified, beforeMtime))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	var body configWriteAPIResponse
	decodeJSON(t, response, &body)
	if want := strconv.FormatInt(fileMtime(t, fixture.configPath), 10); body.Mtime == "0" || body.Mtime != want {
		t.Errorf("mtime = %q, want new file mtime %q", body.Mtime, want)
	}
	written, err := os.ReadFile(fixture.configPath)
	if err != nil {
		t.Fatalf("read written config: %v", err)
	}
	if !bytes.Contains(written, []byte("level: debug")) {
		t.Errorf("written config = %q, want logging level debug", written)
	}
	if fixture.reloadCalls != 1 {
		t.Fatalf("reload calls = %d, want 1", fixture.reloadCalls)
	}
	if fixture.applied == nil || fixture.applied.Logging.Level != "debug" {
		t.Fatalf("applied config = %#v, want logging level debug", fixture.applied)
	}
}

func TestRawConfigAPIRejectsStaleMtime(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	original, err := os.ReadFile(fixture.configPath)
	if err != nil {
		t.Fatalf("read original config: %v", err)
	}
	mtime := fileMtime(t, fixture.configPath)
	modified := strings.Replace(configAPITestYAML, "level: info", "level: debug", 1)
	response := performJSONRequest(t, fixture.server, http.MethodPut, "/api/config/raw", rawWriteRequest(t, modified, mtime-1))

	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusConflict, response.Body.String())
	}
	var body configWriteAPIResponse
	decodeJSON(t, response, &body)
	if body.CurrentMtime != strconv.FormatInt(mtime, 10) || !strings.Contains(body.Error, "changed on disk") {
		t.Errorf("response = %#v, want current mtime %d and changed-on-disk error", body, mtime)
	}
	assertConfigFileBytes(t, fixture.configPath, original)
	if fixture.reloadCalls != 0 {
		t.Errorf("reload calls = %d, want 0", fixture.reloadCalls)
	}
}

func TestRawConfigAPIRejectsInvalidYAML(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	original, err := os.ReadFile(fixture.configPath)
	if err != nil {
		t.Fatalf("read original config: %v", err)
	}
	response := performJSONRequest(t, fixture.server, http.MethodPut, "/api/config/raw", rawWriteRequest(t, "unknown_setting: true\n", fileMtime(t, fixture.configPath)))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusBadRequest, response.Body.String())
	}
	var body configWriteAPIResponse
	decodeJSON(t, response, &body)
	if !strings.Contains(body.Error, "unknown_setting") {
		t.Errorf("error = %q, want unknown-field detail", body.Error)
	}
	assertConfigFileBytes(t, fixture.configPath, original)
	if fixture.reloadCalls != 0 {
		t.Errorf("reload calls = %d, want 0", fixture.reloadCalls)
	}
}

func TestRawConfigAPIRejectsMissingConfigPath(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	response := performJSONRequest(t, server, http.MethodPut, "/api/config/raw", rawWriteRequest(t, configAPITestYAML, 0))

	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusConflict, response.Body.String())
	}
	var body configWriteAPIResponse
	decodeJSON(t, response, &body)
	const want = "config file path is not configured; live write-back is unavailable"
	if body.Error != want {
		t.Errorf("error = %q, want %q", body.Error, want)
	}
}

func TestConfigExportDownloadsCurrentYAML(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	response := performJSONRequest(t, fixture.server, http.MethodGet, "/api/config/export", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "application/x-yaml" {
		t.Errorf("Content-Type = %q, want application/x-yaml", got)
	}
	if got := response.Header().Get("Content-Disposition"); got != `attachment; filename="sinkhole-config.yaml"` {
		t.Errorf("Content-Disposition = %q, want attachment filename", got)
	}
	if got := response.Body.String(); got != configAPITestYAML || !strings.Contains(got, "listen:") {
		t.Errorf("body = %q, want current YAML containing listen:", got)
	}
}

func TestConfigImportAppliesValidYAML(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	modified := strings.Replace(configAPITestYAML, "level: info", "level: debug", 1)
	body, contentType := multipartConfigImport(t, []byte(modified))
	response := performConfigMultipartRequest(t, fixture.server, "/api/config/import", body, contentType)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	var result configWriteAPIResponse
	decodeJSON(t, response, &result)
	if want := strconv.FormatInt(fileMtime(t, fixture.configPath), 10); result.Mtime == "0" || result.Mtime != want {
		t.Errorf("mtime = %q, want new file mtime %q", result.Mtime, want)
	}
	written, err := os.ReadFile(fixture.configPath)
	if err != nil {
		t.Fatalf("read imported config: %v", err)
	}
	if !bytes.Contains(written, []byte("level: debug")) {
		t.Errorf("written config = %q, want logging level debug", written)
	}
	if fixture.reloadCalls != 1 {
		t.Fatalf("reload calls = %d, want 1", fixture.reloadCalls)
	}
	if fixture.applied == nil || fixture.applied.Logging.Level != "debug" {
		t.Fatalf("applied config = %#v, want logging level debug", fixture.applied)
	}
}

func TestConfigImportRejectsInvalidYAML(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	original, err := os.ReadFile(fixture.configPath)
	if err != nil {
		t.Fatalf("read original config: %v", err)
	}
	body, contentType := multipartConfigImport(t, []byte("unknown_setting: true\n"))
	response := performConfigMultipartRequest(t, fixture.server, "/api/config/import", body, contentType)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusBadRequest, response.Body.String())
	}
	var result configWriteAPIResponse
	decodeJSON(t, response, &result)
	if !strings.Contains(result.Error, "unknown_setting") {
		t.Errorf("error = %q, want unknown-field detail", result.Error)
	}
	assertConfigFileBytes(t, fixture.configPath, original)
	if fixture.reloadCalls != 0 {
		t.Errorf("reload calls = %d, want 0", fixture.reloadCalls)
	}
}

func TestConfigImportRejectsOversizedUpload(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	body, contentType := multipartConfigImport(t, bytes.Repeat([]byte("A"), (1<<20)+1))
	response := performConfigMultipartRequest(t, fixture.server, "/api/config/import", body, contentType)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusRequestEntityTooLarge, response.Body.String())
	}
	if fixture.reloadCalls != 0 {
		t.Errorf("reload calls = %d, want 0", fixture.reloadCalls)
	}
}

func TestConfigImportRejectsMissingConfigPath(t *testing.T) {
	server := newTestServer(t, config.AdminConfig{})
	saveTestCredential(t, server, "correct horse battery staple")
	body, contentType := multipartConfigImport(t, []byte(configAPITestYAML))
	response := performConfigMultipartRequest(t, server, "/api/config/import", body, contentType)

	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusConflict, response.Body.String())
	}
	var result configWriteAPIResponse
	decodeJSON(t, response, &result)
	const want = "config file path is not configured; live write-back is unavailable"
	if result.Error != want {
		t.Errorf("error = %q, want %q", result.Error, want)
	}
}

func TestConfigImportExportRequireAuthentication(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	for _, test := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/api/config/export"},
		{method: http.MethodPost, path: "/api/config/import"},
	} {
		t.Run(test.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			fixture.server.Handler().ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
			if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
				t.Errorf("status/location = %d/%q, want %d/%q", response.Code, response.Header().Get("Location"), http.StatusSeeOther, "/login")
			}
		})
	}
}

func TestConfigAPIRequiresAuthentication(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	response := httptest.NewRecorder()

	fixture.server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/config", nil))

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
		t.Errorf("status/location = %d/%q, want %d/%q", response.Code, response.Header().Get("Location"), http.StatusSeeOther, "/login")
	}
}

func TestConfigGETAPIsRejectOtherMethods(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	for _, path := range []string{"/api/config", "/api/config/raw"} {
		t.Run(path, func(t *testing.T) {
			response := performJSONRequest(t, fixture.server, http.MethodPost, path, nil)
			if response.Code != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func newConfigAPIFixture(t *testing.T) *configAPIFixture {
	t.Helper()
	d, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	configPath := d.Path("config.yaml")
	if err := os.WriteFile(configPath, []byte(configAPITestYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	fixture := &configAPIFixture{configPath: configPath}
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

func performConfigMultipartRequest(t *testing.T, server *Server, path string, body []byte, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	request.AddCookie(validSessionCookie(t, server))
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "test-csrf"})
	request.Header.Set("X-CSRF-Token", "test-csrf")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func multipartConfigImport(t *testing.T, data []byte) ([]byte, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	file, err := writer.CreateFormFile("file", "config.yaml")
	if err != nil {
		t.Fatalf("create multipart file: %v", err)
	}
	if _, err := file.Write(data); err != nil {
		t.Fatalf("write multipart file: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart body: %v", err)
	}
	return body.Bytes(), writer.FormDataContentType()
}

func rawWriteRequest(t *testing.T, raw string, mtime any) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"raw": raw, "mtime": mtime})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return data
}

func structuredWriteRequest(t *testing.T, cfg map[string]any, mtime any) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"config": cfg, "mtime": mtime})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return data
}

func fileMtime(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	return info.ModTime().UnixNano()
}

func mustParseMtime(t *testing.T, value string) int64 {
	t.Helper()
	mtime, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		t.Fatalf("parse mtime %q: %v", value, err)
	}
	return mtime
}

func assertConfigFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("file bytes = %q, want unchanged %q", got, want)
	}
}
