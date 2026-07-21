package admin

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/config"
	"github.com/huntastikus/sinkhole-responder/internal/state"
)

const testAdminPassword = "correct horse battery staple"

type tlsTestEnvironment struct {
	server     *Server
	state      *state.Dir
	configPath string
}

func newTLSTestEnvironment(t *testing.T) tlsTestEnvironment {
	t.Helper()

	stateDir, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("create state directory: %v", err)
	}
	cfg, err := config.ParseBytes(nil, stateDir.Root)
	if err != nil {
		t.Fatalf("create default config: %v", err)
	}
	configPath := stateDir.Path("config.yaml")
	if configPath == "" {
		t.Fatal("resolve config path: got empty path")
	}
	raw, err := config.MarshalConfig(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := stateDir.WriteAtomic("config.yaml", raw, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	current := cfg
	server := newTestServer(t, cfg.Admin)
	server.deps.State = stateDir
	server.sessionKey, err = LoadOrCreateSessionKey(stateDir)
	if err != nil {
		t.Fatalf("load session key: %v", err)
	}
	var logs bytes.Buffer
	server.logger = slog.New(slog.NewTextHandler(&logs, nil))
	t.Cleanup(func() { assertNoPrivateKey(t, logs.Bytes()) })
	server.deps.Cfg = func() *config.Config { return current }
	server.deps.Reload = func(next *config.Config) error {
		current = next
		return nil
	}
	server.deps.ConfigPath = configPath
	saveTestCredential(t, server, testAdminPassword)

	return tlsTestEnvironment{server: server, state: stateDir, configPath: configPath}
}

func TestGenerateCADownloadAndTLSStatus(t *testing.T) {
	env := newTLSTestEnvironment(t)

	generate := serveTLSRequest(t, env.server.router, http.MethodPost, "/api/ca/generate", strings.NewReader(`{"cn":"Test Local CA","years":2}`), "application/json", nil)
	if generate.Code != http.StatusOK {
		t.Fatalf("generate status = %d, want %d; body=%s", generate.Code, http.StatusOK, generate.Body.String())
	}
	assertNoPrivateKey(t, generate.Body.Bytes())
	var generated struct {
		Fingerprint string `json:"fingerprint"`
		CertPath    string `json:"cert_path"`
		KeyPath     string `json:"key_path"`
		Warning     string `json:"warning"`
	}
	decodeJSON(t, generate, &generated)
	if generated.Fingerprint == "" || generated.Warning == "" {
		t.Fatalf("generate response missing fingerprint or warning: %+v", generated)
	}
	if generated.CertPath != env.state.Path("tls", "ca.cert.pem") || generated.KeyPath != env.state.Path("tls", "ca.key.pem") {
		t.Fatalf("generate paths = (%q, %q), want state TLS paths", generated.CertPath, generated.KeyPath)
	}
	assertFileMode(t, generated.CertPath, 0o644)
	assertFileMode(t, generated.KeyPath, 0o600)

	// Generating again must reuse the existing CA (e.g. one auto-generated at
	// boot) rather than refuse to overwrite it.
	regenerate := serveTLSRequest(t, env.server.router, http.MethodPost, "/api/ca/generate", strings.NewReader(`{}`), "application/json", nil)
	if regenerate.Code != http.StatusOK {
		t.Fatalf("second generate status = %d, want %d; body=%s", regenerate.Code, http.StatusOK, regenerate.Body.String())
	}
	var regenerated struct {
		Fingerprint string `json:"fingerprint"`
	}
	decodeJSON(t, regenerate, &regenerated)
	if regenerated.Fingerprint != generated.Fingerprint {
		t.Fatalf("second generate fingerprint = %q, want existing %q", regenerated.Fingerprint, generated.Fingerprint)
	}

	download := serveTLSRequest(t, env.server.Handler(), http.MethodGet, "/api/ca/download", nil, "", validSessionCookie(t, env.server))
	if download.Code != http.StatusOK {
		t.Fatalf("download status = %d, want %d; body=%s", download.Code, http.StatusOK, download.Body.String())
	}
	if got := download.Header().Get("Content-Disposition"); got != `attachment; filename="sinkhole-ca.crt"` {
		t.Fatalf("Content-Disposition = %q", got)
	}
	if !bytes.HasPrefix(download.Body.Bytes(), []byte("-----BEGIN CERTIFICATE-----")) {
		t.Fatalf("download body does not start with a certificate: %q", download.Body.String())
	}
	assertNoPrivateKey(t, download.Body.Bytes())

	mtime, err := configFileMtime(env.configPath)
	if err != nil {
		t.Fatalf("config mtime: %v", err)
	}
	modeBody := map[string]any{
		"mode":         "local-ca",
		"mtime":        strconv.FormatInt(mtime, 10),
		"ca_cert":      generated.CertPath,
		"ca_key":       generated.KeyPath,
		"https_listen": []string{"0.0.0.0:443"},
	}
	mode := serveJSONRequest(t, env.server.router, http.MethodPost, "/api/tls/mode", modeBody)
	if mode.Code != http.StatusOK {
		t.Fatalf("mode status = %d, want %d; body=%s", mode.Code, http.StatusOK, mode.Body.String())
	}
	assertNoPrivateKey(t, mode.Body.Bytes())
	var modeResponse struct {
		Mtime           string `json:"mtime"`
		RestartRequired bool   `json:"restart_required"`
	}
	decodeJSON(t, mode, &modeResponse)
	if !modeResponse.RestartRequired || modeResponse.Mtime == "0" {
		t.Fatalf("mode response = %+v", modeResponse)
	}
	written, err := config.Load(env.configPath)
	if err != nil {
		t.Fatalf("load written config: %v", err)
	}
	if written.TLS.Mode != "local-ca" {
		t.Fatalf("written TLS mode = %q, want local-ca", written.TLS.Mode)
	}

	status := serveTLSRequest(t, env.server.Handler(), http.MethodGet, "/api/tls", nil, "", validSessionCookie(t, env.server))
	if status.Code != http.StatusOK {
		t.Fatalf("TLS status = %d, want %d; body=%s", status.Code, http.StatusOK, status.Body.String())
	}
	assertNoPrivateKey(t, status.Body.Bytes())
	var current struct {
		Mode string `json:"mode"`
		CA   *struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"ca"`
	}
	decodeJSON(t, status, &current)
	if current.Mode != "local-ca" || current.CA == nil || current.CA.Fingerprint != generated.Fingerprint {
		t.Fatalf("TLS status = %+v, want active CA fingerprint %q", current, generated.Fingerprint)
	}

	stale := serveJSONRequest(t, env.server.router, http.MethodPost, "/api/tls/mode", modeBody)
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale mode status = %d, want %d; body=%s", stale.Code, http.StatusConflict, stale.Body.String())
	}
	assertNoPrivateKey(t, stale.Body.Bytes())
	var staleResponse struct {
		CurrentMtime string `json:"current_mtime"`
	}
	decodeJSON(t, stale, &staleResponse)
	if want := strconv.FormatInt(fileMtime(t, env.configPath), 10); staleResponse.CurrentMtime != want {
		t.Fatalf("stale current_mtime = %q, want %q", staleResponse.CurrentMtime, want)
	}

	invalidDisabled := serveJSONRequest(t, env.server.router, http.MethodPost, "/api/tls/mode", map[string]any{
		"mode":         "disabled",
		"mtime":        modeResponse.Mtime,
		"https_listen": []string{"0.0.0.0:443"},
	})
	if invalidDisabled.Code != http.StatusBadRequest {
		t.Fatalf("disabled with HTTPS status = %d, want %d; body=%s", invalidDisabled.Code, http.StatusBadRequest, invalidDisabled.Body.String())
	}
	assertNoPrivateKey(t, invalidDisabled.Body.Bytes())
}

func TestTLSUpload(t *testing.T) {
	env := newTLSTestEnvironment(t)
	certPEM, keyPEM := testCertificatePair(t, []string{"sinkhole.test", "alt.sinkhole.test"})

	body, contentType := multipartTLSUpload(t, certPEM, keyPEM, "")
	response := serveTLSRequest(t, env.server.router, http.MethodPost, "/api/tls/upload", body, contentType, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("upload status = %d, want %d; body=%s", response.Code, http.StatusOK, response.Body.String())
	}
	assertNoPrivateKey(t, response.Body.Bytes())
	var uploaded struct {
		Hosts       []string `json:"hosts"`
		CertPath    string   `json:"cert_path"`
		KeyPath     string   `json:"key_path"`
		Fingerprint string   `json:"fingerprint"`
	}
	decodeJSON(t, response, &uploaded)
	if len(uploaded.Hosts) != 2 || uploaded.Hosts[0] != "sinkhole.test" || uploaded.Fingerprint == "" {
		t.Fatalf("upload response = %+v", uploaded)
	}
	assertFileMode(t, uploaded.CertPath, 0o644)
	assertFileMode(t, uploaded.KeyPath, 0o600)
	if _, err := os.Stat(uploaded.CertPath); err != nil {
		t.Fatalf("stat uploaded certificate: %v", err)
	}
}

func TestTLSUploadRejectsMismatchAndOversize(t *testing.T) {
	env := newTLSTestEnvironment(t)
	certPEM, _ := testCertificatePair(t, []string{"one.test"})
	_, otherKeyPEM := testCertificatePair(t, []string{"two.test"})

	body, contentType := multipartTLSUpload(t, certPEM, otherKeyPEM, "one.test")
	mismatch := serveTLSRequest(t, env.server.router, http.MethodPost, "/api/tls/upload", body, contentType, nil)
	if mismatch.Code != http.StatusBadRequest {
		t.Fatalf("mismatched upload status = %d, want %d; body=%s", mismatch.Code, http.StatusBadRequest, mismatch.Body.String())
	}
	if got := strings.TrimSpace(mismatch.Body.String()); got != `{"error":"certificate and key do not match or are invalid"}` {
		t.Fatalf("mismatched upload body = %s", got)
	}
	assertNoPrivateKey(t, mismatch.Body.Bytes())

	body, contentType = multipartTLSUpload(t, bytes.Repeat([]byte("A"), (64<<10)+1), otherKeyPEM, "oversize.test")
	oversized := serveTLSRequest(t, env.server.router, http.MethodPost, "/api/tls/upload", body, contentType, nil)
	if oversized.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload status = %d, want %d; body=%s", oversized.Code, http.StatusRequestEntityTooLarge, oversized.Body.String())
	}
	if got := strings.TrimSpace(oversized.Body.String()); got != `{"error":"certificate or key exceeds 64 KiB"}` {
		t.Fatalf("oversized upload body = %s", got)
	}
	assertNoPrivateKey(t, oversized.Body.Bytes())
}

func TestTLSRoutesRequireAuthenticationAndMethods(t *testing.T) {
	env := newTLSTestEnvironment(t)

	unauthenticated := serveTLSRequest(t, env.server.Handler(), http.MethodPost, "/api/ca/generate", strings.NewReader(`{}`), "application/json", nil)
	if unauthenticated.Code != http.StatusSeeOther || unauthenticated.Header().Get("Location") != "/login" {
		t.Fatalf("unauthenticated generate = %d Location=%q, want 303 /login", unauthenticated.Code, unauthenticated.Header().Get("Location"))
	}

	wrongMethod := serveTLSRequest(t, env.server.router, http.MethodPost, "/api/ca/download", nil, "", nil)
	if wrongMethod.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method status = %d, want %d", wrongMethod.Code, http.StatusMethodNotAllowed)
	}
}

func serveJSONRequest(t *testing.T, handler http.Handler, method, path string, value any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return serveTLSRequest(t, handler, method, path, bytes.NewReader(body), "application/json", nil)
}

func serveTLSRequest(t *testing.T, handler http.Handler, method, path string, body io.Reader, contentType string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, body)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func multipartTLSUpload(t *testing.T, certPEM, keyPEM []byte, hosts string) (*bytes.Reader, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	certPart, err := writer.CreateFormFile("cert", "certificate.pem")
	if err != nil {
		t.Fatalf("create cert part: %v", err)
	}
	if _, err := certPart.Write(certPEM); err != nil {
		t.Fatalf("write cert part: %v", err)
	}
	keyPart, err := writer.CreateFormFile("key", "key.pem")
	if err != nil {
		t.Fatalf("create key part: %v", err)
	}
	if _, err := keyPart.Write(keyPEM); err != nil {
		t.Fatalf("write key part: %v", err)
	}
	if hosts != "" {
		if err := writer.WriteField("hosts", hosts); err != nil {
			t.Fatalf("write hosts field: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart body: %v", err)
	}
	return bytes.NewReader(body.Bytes()), writer.FormDataContentType()
}

func testCertificatePair(t *testing.T, hosts []string) ([]byte, []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0]},
		DNSNames:     hosts,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode for %q = %#o, want %#o", path, got, want)
	}
}

func assertNoPrivateKey(t *testing.T, body []byte) {
	t.Helper()
	if bytes.Contains(body, []byte("PRIVATE KEY")) {
		t.Fatalf("response exposed private key material: %q", body)
	}
}
