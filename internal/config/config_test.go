package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/rules"
)

var overrideEnvironment = []string{
	"SINKHOLE_LISTEN_HTTP",
	"SINKHOLE_LISTEN_HTTPS",
	"SINKHOLE_MANAGEMENT_LISTEN",
	"SINKHOLE_TLS_MODE",
	"SINKHOLE_DEFAULTS_STATUS",
	"SINKHOLE_LOG_LEVEL",
	"SINKHOLE_ACCESS_LOG",
}

func TestLoadEmptyFileUsesDefaults(t *testing.T) {
	clearOverrides(t)
	path := writeConfig(t, "")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	managementEnabled := true
	accessLog := true
	anonymizeClient := true
	want := &Config{
		Listen: ListenConfig{
			HTTP:  []string{"0.0.0.0:80"},
			HTTPS: []string{"0.0.0.0:443"},
		},
		Management: MgmtConfig{
			Enabled: &managementEnabled,
			Listen:  "127.0.0.1:9090",
		},
		TLS: TLSConfig{
			Mode:   "local-ca",
			Static: TLSStatic{Certs: []CertPair{}},
			LocalCA: TLSLocalCA{
				CacheSize: 1024,
				LeafTTL:   24 * time.Hour,
			},
		},
		Defaults: DefaultsConfig{
			Status:        200,
			BeaconStatus:  200,
			MediaResponse: "204",
			CacheControl:  "no-store",
		},
		Limits: LimitsConfig{
			MaxHeaderBytes: 16384,
			MaxBodyBytes:   65536,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			IdleTimeout:    60 * time.Second,
			RateBurst:      50,
		},
		Logging: LoggingConfig{
			Level:           "info",
			AccessLog:       &accessLog,
			AnonymizeClient: &anonymizeClient,
		},
		JSONP: JSONPConfig{Param: "callback"},
		Admin: AdminConfig{
			Listen:         "0.0.0.0:8080",
			TLS:            AdminTLS{Enabled: true, Listen: "0.0.0.0:8443", RedirectHTTP: true},
			SessionTTL:     12 * time.Hour,
			LoginRatePerIP: 0.2,
			LoginBurst:     5,
		},
		Rulepacks: RulepacksConfig{Enabled: []string{}},
		Rules:     []rules.Rule{},
		ConfigDir: filepath.Dir(path),
	}

	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("Load() = %#v, want %#v", cfg, want)
	}
}

func TestWriteDefaultConfigRoundTrips(t *testing.T) {
	clearOverrides(t)
	path := filepath.Join(t.TempDir(), "state", "config.yaml")

	if err := WriteDefaultConfig(path); err != nil {
		t.Fatalf("WriteDefaultConfig() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat default config: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("default config mode = %o, want 600", got)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !cfg.Admin.Enabled {
		t.Fatal("Admin.Enabled = false, want true")
	}
	if err := WriteDefaultConfig(path); err == nil {
		t.Fatal("second WriteDefaultConfig() error = nil, want existing-file error")
	}
}

func TestLoadFullAdminBlock(t *testing.T) {
	clearOverrides(t)
	path := writeConfig(t, `
state_dir: /var/lib/sinkhole-responder
admin:
  enabled: true
  listen: "127.0.0.1:18080"
  tls:
    enabled: true
    listen: "127.0.0.1:18443"
    cert_file: admin.pem
    key_file: admin-key.pem
    redirect_http: false
  session_ttl: "30m"
  login_rate_per_ip: 1.5
  login_burst: 9
rulepacks:
  enabled: [recommended, gpt]
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	wantAdmin := AdminConfig{
		Enabled: true,
		Listen:  "127.0.0.1:18080",
		TLS: AdminTLS{
			Enabled:  true,
			Listen:   "127.0.0.1:18443",
			CertFile: "admin.pem",
			KeyFile:  "admin-key.pem",
		},
		SessionTTL:     30 * time.Minute,
		LoginRatePerIP: 1.5,
		LoginBurst:     9,
	}
	if !reflect.DeepEqual(cfg.Admin, wantAdmin) {
		t.Fatalf("Admin = %#v, want %#v", cfg.Admin, wantAdmin)
	}
	if cfg.StateDir != "/var/lib/sinkhole-responder" {
		t.Fatalf("StateDir = %q, want /var/lib/sinkhole-responder", cfg.StateDir)
	}
	wantRulepacks := []string{"recommended", "gpt"}
	if !reflect.DeepEqual(cfg.Rulepacks.Enabled, wantRulepacks) {
		t.Fatalf("Rulepacks.Enabled = %v, want %v", cfg.Rulepacks.Enabled, wantRulepacks)
	}
}

func TestLoadRejectsUnknownAdminKey(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{name: "admin", yaml: "admin:\n  unknown: true\n"},
		{name: "admin TLS", yaml: "admin:\n  tls:\n    unknown: true\n"},
		{name: "rulepacks", yaml: "rulepacks:\n  unknown: true\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearOverrides(t)
			path := writeConfig(t, tt.yaml)

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), "field unknown not found") {
				t.Fatalf("Load() error = %v, want unknown field error", err)
			}
		})
	}
}

func TestLoadRejectsEnabledAdminWithoutListen(t *testing.T) {
	clearOverrides(t)
	path := writeConfig(t, "admin:\n  enabled: true\n  listen: \"\"\n")

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "admin.listen") {
		t.Fatalf("Load() error = %v, want admin.listen validation error", err)
	}
}

func TestLoadV1ConfigStillLoads(t *testing.T) {
	clearOverrides(t)
	path := writeConfig(t, `
listen:
  http: ["127.0.0.1:8080"]
  https: []
management:
  enabled: true
  listen: "127.0.0.1:9090"
tls:
  mode: disabled
defaults:
  status: 204
logging:
  level: warn
rules: []
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() v1 config error = %v", err)
	}
	if !reflect.DeepEqual(cfg.Listen.HTTP, []string{"127.0.0.1:8080"}) || cfg.Defaults.Status != 204 || cfg.Logging.Level != "warn" {
		t.Fatalf("Load() v1 fields = listen %v, status %d, level %q", cfg.Listen.HTTP, cfg.Defaults.Status, cfg.Logging.Level)
	}
}

func TestEnvironmentOverridesYAML(t *testing.T) {
	clearOverrides(t)
	t.Setenv("SINKHOLE_DEFAULTS_STATUS", "204")
	t.Setenv("SINKHOLE_LISTEN_HTTP", "127.0.0.1:8000, 127.0.0.1:8001")
	t.Setenv("SINKHOLE_ACCESS_LOG", "false")
	path := writeConfig(t, `
listen:
  http: ["0.0.0.0:9000"]
defaults:
  status: 201
logging:
  access_log: true
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Defaults.Status != 204 {
		t.Errorf("Defaults.Status = %d, want 204", cfg.Defaults.Status)
	}
	wantHTTP := []string{"127.0.0.1:8000", "127.0.0.1:8001"}
	if !reflect.DeepEqual(cfg.Listen.HTTP, wantHTTP) {
		t.Errorf("Listen.HTTP = %v, want %v", cfg.Listen.HTTP, wantHTTP)
	}
	if cfg.Logging.AccessLog == nil || *cfg.Logging.AccessLog {
		t.Errorf("Logging.AccessLog = %v, want false", cfg.Logging.AccessLog)
	}
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{name: "status below range", yaml: "defaults:\n  status: 99\n", wantErr: "defaults.status"},
		{name: "status above range", yaml: "defaults:\n  status: 600\n", wantErr: "defaults.status"},
		{name: "invalid TLS mode", yaml: "tls:\n  mode: tls\n", wantErr: "tls.mode"},
		{name: "invalid media response", yaml: "defaults:\n  media_response: foo\n", wantErr: "defaults.media_response"},
		{name: "invalid log level", yaml: "logging:\n  level: trace\n", wantErr: "logging.level"},
		{name: "HTTPS with TLS disabled", yaml: "listen:\n  https: [\":8443\"]\ntls:\n  mode: disabled\n", wantErr: "listen.https"},
		{name: "static TLS without certs", yaml: "tls:\n  mode: static\nlisten:\n  https: [\":8443\"]\n", wantErr: "tls.static.certs"},
		{name: "local CA zero cache", yaml: localCATestYAML("    cache_size: 0\n"), wantErr: "cache_size"},
		{name: "local CA cache below minimum", yaml: localCATestYAML("    cache_size: -1\n"), wantErr: "cache_size"},
		{name: "local CA leaf TTL below one minute", yaml: localCATestYAML("    leaf_ttl: 30s\n"), wantErr: "at least 1 minute"},
		{name: "local CA zero leaf TTL", yaml: localCATestYAML("    leaf_ttl: 0s\n"), wantErr: "at least 1 minute"},
		{name: "local CA negative leaf TTL", yaml: localCATestYAML("    leaf_ttl: -1m\n"), wantErr: "at least 1 minute"},
		{name: "no data-plane listeners", yaml: "listen:\n  http: []\n  https: []\n", wantErr: "at least one listen.http or listen.https"},
		{name: "invalid HTTP listen", yaml: "listen:\n  http: [localhost]\n", wantErr: "listen.http[0]"},
		{name: "invalid HTTPS listen", yaml: "listen:\n  https: [localhost]\ntls:\n  mode: static\n  static:\n    certs:\n      - cert_file: leaf.pem\n        key_file: leaf-key.pem\n", wantErr: "listen.https[0]"},
		{name: "invalid management listen", yaml: "management:\n  listen: localhost\n", wantErr: "management.listen"},
		{name: "external management without opt-in", yaml: "management:\n  listen: 0.0.0.0:9090\n", wantErr: "management.allow_external"},
		{name: "hostname management listen", yaml: "management:\n  listen: sinkhole.test:9090\n", wantErr: "management.allow_external"},
		{name: "rule delay equals write timeout", yaml: "limits:\n  write_timeout: 25ms\nrules:\n  - response:\n      delay_ms: 25\n", wantErr: "delay_ms 25 must be less than write_timeout 25ms"},
		{name: "invalid admin listen", yaml: "admin:\n  enabled: true\n  listen: localhost\n", wantErr: "admin.listen"},
		{name: "enabled admin TLS without listen", yaml: "admin:\n  enabled: true\n  tls:\n    enabled: true\n    listen: \"\"\n", wantErr: "admin.tls.listen"},
		{name: "zero admin session TTL", yaml: "admin:\n  session_ttl: 0s\n", wantErr: "admin.session_ttl"},
		{name: "negative admin login rate", yaml: "admin:\n  login_rate_per_ip: -1\n", wantErr: "admin.login_rate_per_ip"},
		{name: "positive admin login rate without burst", yaml: "admin:\n  login_rate_per_ip: 1\n  login_burst: 0\n", wantErr: "admin.login_burst"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearOverrides(t)
			path := writeConfig(t, tt.yaml)

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestLocalCAPathsMayBeEmptyOnlyAsAPair(t *testing.T) {
	tests := []struct {
		name    string
		cert    string
		key     string
		wantErr bool
	}{
		{name: "auto-generated"},
		{name: "configured pair", cert: "ca.pem", key: "ca-key.pem"},
		{name: "certificate only", cert: "ca.pem", wantErr: true},
		{name: "key only", key: "ca-key.pem", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := defaultConfig()
			cfg.TLS.LocalCA.CACert = test.cert
			cfg.TLS.LocalCA.CAKey = test.key
			err := cfg.Validate()
			if test.wantErr && (err == nil || !strings.Contains(err.Error(), "must be set together")) {
				t.Fatalf("Validate() error = %v, want paired-path error", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestLoadStaticAllowsHostsOmitted(t *testing.T) {
	clearOverrides(t)
	path := writeConfig(t, `
listen:
  https: [":8443"]
tls:
  mode: static
  static:
    certs:
      - cert_file: leaf.pem
        key_file: leaf-key.pem
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.TLS.Static.Certs) != 1 || len(cfg.TLS.Static.Certs[0].Hosts) != 0 {
		t.Fatalf("static certificates = %#v, want one pair with omitted hosts", cfg.TLS.Static.Certs)
	}
}

func localCATestYAML(extra string) string {
	return "listen:\n  https: [\":8443\"]\ntls:\n  mode: local-ca\n  local_ca:\n    ca_cert: ca.pem\n    ca_key: ca-key.pem\n" + extra
}

func TestLoadAllowsConfiguredManagementAndRuleDelay(t *testing.T) {
	clearOverrides(t)
	path := writeConfig(t, `
management:
  listen: sinkhole.test:9090
  allow_external: true
limits:
  write_timeout: 26ms
rules:
  - response:
      delay_ms: 25
`)

	if _, err := Load(path); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestValidateDoesNotMutate(t *testing.T) {
	cfg := defaultConfig()
	cfg.TLS.Mode = "local-ca"
	cfg.Listen.HTTPS = []string{"127.0.0.1:8443"}
	cfg.TLS.LocalCA.CACert = "ca.pem"
	cfg.TLS.LocalCA.CAKey = "ca-key.pem"
	cfg.TLS.LocalCA.CacheSize = 0

	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "cache_size") {
		t.Fatalf("Validate() error = %v, want cache_size error", err)
	}
	if cfg.TLS.LocalCA.CacheSize != 0 {
		t.Fatalf("Validate() mutated CacheSize to %d", cfg.TLS.LocalCA.CacheSize)
	}
}

func TestLoadRejectsUnknownTopLevelKey(t *testing.T) {
	clearOverrides(t)
	path := writeConfig(t, "unknown: true\n")

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("Load() error = %v, want unknown field error", err)
	}
}

func TestLoadDecodesRules(t *testing.T) {
	clearOverrides(t)
	path := writeConfig(t, `
rules:
  - name: image ads
    host: Ads.Example.COM
    host_glob: "*.example.com"
    path_glob: /ads/*
    path_regex: '^/ads/.+$'
    method: GET
    sec_fetch_dest: image
    accept: image/
    query:
      v: "2"
    headers:
      x-requested-with: XMLHttpRequest
    response:
      status: 204
      content_type: image/gif
      body_base64: R0lG
      headers:
        Cache-Control: no-store
      delay_ms: 25
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := rules.Rule{
		Name:         "image ads",
		Host:         "Ads.Example.COM",
		HostGlob:     "*.example.com",
		PathGlob:     "/ads/*",
		PathRegex:    "^/ads/.+$",
		Method:       "GET",
		SecFetchDest: "image",
		Accept:       "image/",
		Query:        map[string]string{"v": "2"},
		Headers:      map[string]string{"x-requested-with": "XMLHttpRequest"},
		Response: rules.Response{
			Status:      204,
			ContentType: "image/gif",
			BodyBase64:  "R0lG",
			Headers:     map[string]string{"Cache-Control": "no-store"},
			DelayMS:     25,
		},
	}
	if len(cfg.Rules) != 1 || !reflect.DeepEqual(cfg.Rules[0], want) {
		t.Fatalf("Rules = %#v, want %#v", cfg.Rules, want)
	}
}

func TestLoadRejectsUnknownRuleFields(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		key  string
	}{
		{name: "rule", yaml: "rules:\n  - hots: ads.example.com\n", key: "hots"},
		{name: "response", yaml: "rules:\n  - host: ads.example.com\n    response:\n      statues: 204\n", key: "statues"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearOverrides(t)
			path := writeConfig(t, tt.yaml)
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), "field "+tt.key+" not found") {
				t.Fatalf("Load() error = %v, want unknown field %q", err, tt.key)
			}
		})
	}
}

func TestLoadParsesDuration(t *testing.T) {
	clearOverrides(t)
	path := writeConfig(t, "limits:\n  read_timeout: 250ms\n")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Limits.ReadTimeout != 250*time.Millisecond {
		t.Fatalf("Limits.ReadTimeout = %v, want 250ms", cfg.Limits.ReadTimeout)
	}
}

func TestLoadSetsAbsoluteConfigDir(t *testing.T) {
	clearOverrides(t)
	path := writeConfig(t, "")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !filepath.IsAbs(cfg.ConfigDir) {
		t.Fatalf("ConfigDir = %q, want an absolute path", cfg.ConfigDir)
	}
	if cfg.ConfigDir != filepath.Dir(path) {
		t.Fatalf("ConfigDir = %q, want %q", cfg.ConfigDir, filepath.Dir(path))
	}
}

func TestParseBytesMatchesLoad(t *testing.T) {
	clearOverrides(t)
	path := writeConfig(t, "listen:\n  http:\n    - 127.0.0.1:8081\nlimits:\n  read_timeout: 250ms\n")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	parsed, err := ParseBytes(data, filepath.Dir(path))
	if err != nil {
		t.Fatalf("ParseBytes() error = %v", err)
	}
	if !reflect.DeepEqual(parsed, loaded) {
		t.Fatalf("ParseBytes() = %#v, want Load() result %#v", parsed, loaded)
	}

	if _, err := ParseBytes([]byte("unknown_setting: true\n"), filepath.Dir(path)); err == nil || !strings.Contains(err.Error(), "unknown_setting") {
		t.Fatalf("ParseBytes() error = %v, want unknown-field error", err)
	}
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func clearOverrides(t *testing.T) {
	t.Helper()
	for _, name := range overrideEnvironment {
		value, present := os.LookupEnv(name)
		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("unset %s: %v", name, err)
		}
		t.Cleanup(func() {
			var err error
			if present {
				err = os.Setenv(name, value)
			} else {
				err = os.Unsetenv(name)
			}
			if err != nil {
				t.Errorf("restore %s: %v", name, err)
			}
		})
	}
}
