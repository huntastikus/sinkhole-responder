package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/rules"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen     ListenConfig    `yaml:"listen"`
	Management MgmtConfig      `yaml:"management"`
	TLS        TLSConfig       `yaml:"tls"`
	Defaults   DefaultsConfig  `yaml:"defaults"`
	Limits     LimitsConfig    `yaml:"limits"`
	Logging    LoggingConfig   `yaml:"logging"`
	JSONP      JSONPConfig     `yaml:"jsonp"`
	StateDir   string          `yaml:"state_dir"`
	Admin      AdminConfig     `yaml:"admin"`
	Rulepacks  RulepacksConfig `yaml:"rulepacks"`
	Rules      []rules.Rule    `yaml:"rules"`
	ConfigDir  string          `yaml:"-"`
}

// RestartRequired reports whether moving from the running baseline to desired
// changes any setting that is bound once at process startup and cannot be
// applied by a live reload: the data-plane listeners, TLS, the management
// listener, request limits, the admin plane's listener and TLS, and the state
// directory. Request-time settings — rules, defaults, JSONP, all logging fields,
// and the admin session/login tuning — are applied live by a reload and are
// intentionally excluded, so reverting a change back to the running values
// clears the requirement.
func RestartRequired(baseline, desired *Config) bool {
	if baseline == nil || desired == nil {
		return false
	}
	return !slices.Equal(baseline.Listen.HTTP, desired.Listen.HTTP) ||
		!slices.Equal(baseline.Listen.HTTPS, desired.Listen.HTTPS) ||
		!reflect.DeepEqual(baseline.TLS, desired.TLS) ||
		!reflect.DeepEqual(baseline.Management, desired.Management) ||
		!reflect.DeepEqual(baseline.Limits, desired.Limits) ||
		baseline.StateDir != desired.StateDir ||
		baseline.Admin.Enabled != desired.Admin.Enabled ||
		baseline.Admin.Listen != desired.Admin.Listen ||
		!reflect.DeepEqual(baseline.Admin.TLS, desired.Admin.TLS)
}

type ListenConfig struct {
	HTTP  []string `yaml:"http"`
	HTTPS []string `yaml:"https"`
}

type MgmtConfig struct {
	Enabled       *bool  `yaml:"enabled"`
	Listen        string `yaml:"listen"`
	AllowExternal bool   `yaml:"allow_external"`
}

type TLSConfig struct {
	Mode    string     `yaml:"mode"`
	Static  TLSStatic  `yaml:"static"`
	LocalCA TLSLocalCA `yaml:"local_ca"`
}

type TLSStatic struct {
	Certs []CertPair `yaml:"certs"`
}

type CertPair struct {
	Hosts    []string `yaml:"hosts"`
	CertFile string   `yaml:"cert_file"`
	KeyFile  string   `yaml:"key_file"`
}

type TLSLocalCA struct {
	CACert    string        `yaml:"ca_cert"`
	CAKey     string        `yaml:"ca_key"`
	CacheSize int           `yaml:"cache_size"`
	LeafTTL   time.Duration `yaml:"leaf_ttl"`
}

type DefaultsConfig struct {
	Status        int    `yaml:"status"`
	BeaconStatus  int    `yaml:"beacon_status"`
	MediaResponse string `yaml:"media_response"`
	CacheControl  string `yaml:"cache_control"`
}

type LimitsConfig struct {
	MaxHeaderBytes int           `yaml:"max_header_bytes"`
	MaxBodyBytes   int64         `yaml:"max_body_bytes"`
	ReadTimeout    time.Duration `yaml:"read_timeout"`
	WriteTimeout   time.Duration `yaml:"write_timeout"`
	IdleTimeout    time.Duration `yaml:"idle_timeout"`
	RatePerIP      float64       `yaml:"rate_per_ip"`
	RateBurst      int           `yaml:"rate_burst"`
}

type LoggingConfig struct {
	Level           string `yaml:"level"`
	AccessLog       *bool  `yaml:"access_log"`
	LogQuery        bool   `yaml:"log_query"`
	AnonymizeClient *bool  `yaml:"anonymize_client"`
}

type JSONPConfig struct {
	Enabled bool   `yaml:"enabled"`
	Param   string `yaml:"param"`
}

type AdminConfig struct {
	Enabled        bool          `yaml:"enabled"`
	Listen         string        `yaml:"listen"`
	TLS            AdminTLS      `yaml:"tls"`
	SessionTTL     time.Duration `yaml:"session_ttl"`
	LoginRatePerIP float64       `yaml:"login_rate_per_ip"`
	LoginBurst     int           `yaml:"login_burst"`
}

type AdminTLS struct {
	Enabled      bool   `yaml:"enabled"`
	Listen       string `yaml:"listen"`
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	RedirectHTTP bool   `yaml:"redirect_http"`
}

type RulepacksConfig struct {
	Enabled []string `yaml:"enabled"`
}

const managedFileBanner = "# Managed by Sinkhole Responder admin UI.\n" +
	"# Manual edits may be overwritten when settings are saved from the web UI."

// MarshalConfig renders cfg as YAML prefixed with a managed-file banner.
func MarshalConfig(cfg *Config) ([]byte, error) {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}

	return append([]byte(managedFileBanner+"\n"), data...), nil
}

// WriteDefaultConfig writes a valid default configuration (admin plane enabled)
// to path if callers need to seed a fresh install. Creates the parent dir 0700
// and the file 0600. Returns an error if the path already exists.
func WriteDefaultConfig(path string) error {
	cfg := defaultConfig()
	cfg.Admin.Enabled = true
	data, err := MarshalConfig(cfg)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create configuration directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("default configuration already exists at %s", path)
		}
		return fmt.Errorf("create default configuration: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write default configuration: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close default configuration: %w", err)
	}
	return nil
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return ParseBytes(data, filepath.Dir(path))
}

// ParseBytes parses YAML config bytes; configDir is stored as Config.ConfigDir
// and used for resolving relative rule and body paths.
func ParseBytes(data []byte, configDir string) (*Config, error) {
	cfg := defaultConfig()
	if len(bytes.TrimSpace(data)) > 0 {
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(cfg); err != nil {
			return nil, fmt.Errorf("decode config: %w", err)
		}
	}

	absDir, err := filepath.Abs(configDir)
	if err != nil {
		return nil, fmt.Errorf("resolve config path: %w", err)
	}
	cfg.ConfigDir = absDir

	if err := applyEnv(cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if len(c.Listen.HTTP) == 0 && len(c.Listen.HTTPS) == 0 {
		return errors.New("at least one listen.http or listen.https address is required")
	}
	for i, address := range c.Listen.HTTP {
		if _, _, err := net.SplitHostPort(address); err != nil {
			return fmt.Errorf("listen.http[%d] must be a valid host:port: %w", i, err)
		}
	}
	for i, address := range c.Listen.HTTPS {
		if _, _, err := net.SplitHostPort(address); err != nil {
			return fmt.Errorf("listen.https[%d] must be a valid host:port: %w", i, err)
		}
	}
	managementDisabled := c.Management.Enabled != nil && !*c.Management.Enabled
	if err := ValidateManagementListen(c.Management.Listen, c.Management.AllowExternal || managementDisabled); err != nil {
		return err
	}

	switch c.TLS.Mode {
	case "disabled", "static", "local-ca":
	default:
		return fmt.Errorf("tls.mode must be disabled, static, or local-ca, got %q", c.TLS.Mode)
	}

	if c.Defaults.Status < 100 || c.Defaults.Status > 599 {
		return fmt.Errorf("defaults.status must be between 100 and 599, got %d", c.Defaults.Status)
	}
	if c.Defaults.BeaconStatus < 100 || c.Defaults.BeaconStatus > 599 {
		return fmt.Errorf("defaults.beacon_status must be between 100 and 599, got %d", c.Defaults.BeaconStatus)
	}
	if c.Defaults.MediaResponse != "204" && c.Defaults.MediaResponse != "asset" {
		return fmt.Errorf("defaults.media_response must be 204 or asset, got %q", c.Defaults.MediaResponse)
	}

	switch c.Logging.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("logging.level must be debug, info, warn, or error, got %q", c.Logging.Level)
	}

	if c.TLS.Mode == "static" {
		if len(c.TLS.Static.Certs) == 0 {
			return errors.New("tls.static.certs must contain at least one certificate pair in static mode")
		}
		for i, cert := range c.TLS.Static.Certs {
			if cert.CertFile == "" || cert.KeyFile == "" {
				return fmt.Errorf("tls.static.certs[%d] requires non-empty cert_file and key_file", i)
			}
			for _, host := range cert.Hosts {
				if host == "" {
					return fmt.Errorf("tls.static.certs[%d].hosts must not contain an empty hostname", i)
				}
			}
		}
	}
	if c.TLS.Mode == "local-ca" {
		if (c.TLS.LocalCA.CACert == "") != (c.TLS.LocalCA.CAKey == "") {
			return errors.New("tls.local_ca.ca_cert and tls.local_ca.ca_key must be set together (leave both empty to auto-generate)")
		}
		if c.TLS.LocalCA.CacheSize < 1 {
			return errors.New("tls.local_ca.cache_size must be at least 1")
		}
		if c.TLS.LocalCA.LeafTTL < time.Minute {
			return errors.New("tls.local_ca.leaf_ttl must be at least 1 minute")
		}
	}

	if len(c.Listen.HTTPS) > 0 && c.TLS.Mode == "disabled" {
		return errors.New("listen.https requires TLS mode static or local-ca")
	}
	if c.TLS.Mode != "disabled" && len(c.Listen.HTTPS) == 0 {
		return errors.New("listen.https must not be empty when TLS is enabled")
	}

	if c.Limits.MaxHeaderBytes < 0 || c.Limits.MaxBodyBytes < 0 || c.Limits.ReadTimeout < 0 ||
		c.Limits.WriteTimeout < 0 || c.Limits.IdleTimeout < 0 || c.Limits.RatePerIP < 0 || c.Limits.RateBurst < 0 {
		return errors.New("limits values must be non-negative")
	}
	if c.Limits.RatePerIP > 0 && c.Limits.RateBurst < 1 {
		return errors.New("limits.rate_burst must be at least 1 when limits.rate_per_ip is positive")
	}
	for _, rule := range c.Rules {
		delay := time.Duration(rule.Response.DelayMS) * time.Millisecond
		if delay > 0 && c.Limits.WriteTimeout > 0 && delay >= c.Limits.WriteTimeout {
			return fmt.Errorf("delay_ms %d must be less than write_timeout %s — the response would always be cut off", rule.Response.DelayMS, c.Limits.WriteTimeout)
		}
	}

	if c.JSONP.Enabled && c.JSONP.Param == "" {
		return errors.New("jsonp.param must not be empty when JSONP is enabled")
	}

	if c.Admin.Enabled {
		if _, _, err := net.SplitHostPort(c.Admin.Listen); err != nil {
			return fmt.Errorf("admin.listen must be a valid host:port: %w", err)
		}
		if c.Admin.TLS.Enabled {
			if _, _, err := net.SplitHostPort(c.Admin.TLS.Listen); err != nil {
				return fmt.Errorf("admin.tls.listen must be a valid host:port: %w", err)
			}
		}
	}
	if c.Admin.SessionTTL <= 0 {
		return errors.New("admin.session_ttl must be positive")
	}
	if c.Admin.LoginRatePerIP < 0 {
		return errors.New("admin.login_rate_per_ip must be non-negative")
	}
	if c.Admin.LoginRatePerIP > 0 && c.Admin.LoginBurst < 1 {
		return errors.New("admin.login_burst must be at least 1 when admin.login_rate_per_ip is positive")
	}

	return nil
}

// ValidateManagementListen enforces the management listener's external-bind policy.
func ValidateManagementListen(address string, allowExternal bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("management.listen must be a valid host:port: %w", err)
	}
	if allowExternal {
		return nil
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("management listener refuses non-loopback bind without management.allow_external: true")
	}
	return nil
}

func defaultConfig() *Config {
	managementEnabled := true
	accessLog := true
	anonymizeClient := true

	return &Config{
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
		JSONP:    JSONPConfig{Param: "callback"},
		StateDir: "",
		Admin: AdminConfig{
			Listen:         "0.0.0.0:8080",
			TLS:            AdminTLS{Enabled: true, Listen: "0.0.0.0:8443", RedirectHTTP: true},
			SessionTTL:     12 * time.Hour,
			LoginRatePerIP: 0.2,
			LoginBurst:     5,
		},
		Rulepacks: RulepacksConfig{Enabled: []string{}},
		Rules:     []rules.Rule{},
	}
}

type yamlDuration time.Duration

func (d *yamlDuration) UnmarshalYAML(node *yaml.Node) error {
	duration, err := time.ParseDuration(node.Value)
	if err != nil {
		return err
	}
	*d = yamlDuration(duration)
	return nil
}

func (c *AdminConfig) UnmarshalYAML(node *yaml.Node) error {
	type rawAdminConfig struct {
		Enabled        bool         `yaml:"enabled"`
		Listen         string       `yaml:"listen"`
		TLS            AdminTLS     `yaml:"tls"`
		SessionTTL     yamlDuration `yaml:"session_ttl"`
		LoginRatePerIP float64      `yaml:"login_rate_per_ip"`
		LoginBurst     int          `yaml:"login_burst"`
	}

	if err := rejectUnknownFields(node, "enabled", "listen", "tls", "session_ttl", "login_rate_per_ip", "login_burst"); err != nil {
		return err
	}
	raw := rawAdminConfig{
		Enabled:        c.Enabled,
		Listen:         c.Listen,
		TLS:            c.TLS,
		SessionTTL:     yamlDuration(c.SessionTTL),
		LoginRatePerIP: c.LoginRatePerIP,
		LoginBurst:     c.LoginBurst,
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	c.Enabled = raw.Enabled
	c.Listen = raw.Listen
	c.TLS = raw.TLS
	c.SessionTTL = time.Duration(raw.SessionTTL)
	c.LoginRatePerIP = raw.LoginRatePerIP
	c.LoginBurst = raw.LoginBurst
	return nil
}

func (c *AdminTLS) UnmarshalYAML(node *yaml.Node) error {
	type rawAdminTLS struct {
		Enabled      bool   `yaml:"enabled"`
		Listen       string `yaml:"listen"`
		CertFile     string `yaml:"cert_file"`
		KeyFile      string `yaml:"key_file"`
		RedirectHTTP bool   `yaml:"redirect_http"`
	}

	if err := rejectUnknownFields(node, "enabled", "listen", "cert_file", "key_file", "redirect_http"); err != nil {
		return err
	}
	raw := rawAdminTLS{
		Enabled:      c.Enabled,
		Listen:       c.Listen,
		CertFile:     c.CertFile,
		KeyFile:      c.KeyFile,
		RedirectHTTP: c.RedirectHTTP,
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	*c = AdminTLS(raw)
	return nil
}

func (c *TLSLocalCA) UnmarshalYAML(node *yaml.Node) error {
	type rawTLSLocalCA struct {
		CACert    string       `yaml:"ca_cert"`
		CAKey     string       `yaml:"ca_key"`
		CacheSize int          `yaml:"cache_size"`
		LeafTTL   yamlDuration `yaml:"leaf_ttl"`
	}

	if err := rejectUnknownFields(node, "ca_cert", "ca_key", "cache_size", "leaf_ttl"); err != nil {
		return err
	}
	raw := rawTLSLocalCA{
		CACert:    c.CACert,
		CAKey:     c.CAKey,
		CacheSize: c.CacheSize,
		LeafTTL:   yamlDuration(c.LeafTTL),
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	c.CACert = raw.CACert
	c.CAKey = raw.CAKey
	c.CacheSize = raw.CacheSize
	c.LeafTTL = time.Duration(raw.LeafTTL)
	return nil
}

func (c *LimitsConfig) UnmarshalYAML(node *yaml.Node) error {
	type rawLimitsConfig struct {
		MaxHeaderBytes int          `yaml:"max_header_bytes"`
		MaxBodyBytes   int64        `yaml:"max_body_bytes"`
		ReadTimeout    yamlDuration `yaml:"read_timeout"`
		WriteTimeout   yamlDuration `yaml:"write_timeout"`
		IdleTimeout    yamlDuration `yaml:"idle_timeout"`
		RatePerIP      float64      `yaml:"rate_per_ip"`
		RateBurst      int          `yaml:"rate_burst"`
	}

	if err := rejectUnknownFields(node, "max_header_bytes", "max_body_bytes", "read_timeout", "write_timeout", "idle_timeout", "rate_per_ip", "rate_burst"); err != nil {
		return err
	}
	raw := rawLimitsConfig{
		MaxHeaderBytes: c.MaxHeaderBytes,
		MaxBodyBytes:   c.MaxBodyBytes,
		ReadTimeout:    yamlDuration(c.ReadTimeout),
		WriteTimeout:   yamlDuration(c.WriteTimeout),
		IdleTimeout:    yamlDuration(c.IdleTimeout),
		RatePerIP:      c.RatePerIP,
		RateBurst:      c.RateBurst,
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	c.MaxHeaderBytes = raw.MaxHeaderBytes
	c.MaxBodyBytes = raw.MaxBodyBytes
	c.ReadTimeout = time.Duration(raw.ReadTimeout)
	c.WriteTimeout = time.Duration(raw.WriteTimeout)
	c.IdleTimeout = time.Duration(raw.IdleTimeout)
	c.RatePerIP = raw.RatePerIP
	c.RateBurst = raw.RateBurst
	return nil
}

func rejectUnknownFields(node *yaml.Node, allowed ...string) error {
	if node.Kind != yaml.MappingNode {
		return nil
	}

	known := make(map[string]struct{}, len(allowed))
	for _, field := range allowed {
		known[field] = struct{}{}
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		field := node.Content[i]
		if _, ok := known[field.Value]; !ok {
			return fmt.Errorf("line %d: field %s not found", field.Line, field.Value)
		}
	}
	return nil
}

func applyEnv(cfg *Config) error {
	if value, ok := os.LookupEnv("SINKHOLE_LISTEN_HTTP"); ok {
		cfg.Listen.HTTP = commaSeparated(value)
	}
	if value, ok := os.LookupEnv("SINKHOLE_LISTEN_HTTPS"); ok {
		cfg.Listen.HTTPS = commaSeparated(value)
	}
	if value, ok := os.LookupEnv("SINKHOLE_MANAGEMENT_LISTEN"); ok {
		cfg.Management.Listen = value
	}
	if value, ok := os.LookupEnv("SINKHOLE_TLS_MODE"); ok {
		cfg.TLS.Mode = value
	}
	if value, ok := os.LookupEnv("SINKHOLE_DEFAULTS_STATUS"); ok {
		status, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("parse SINKHOLE_DEFAULTS_STATUS: %w", err)
		}
		cfg.Defaults.Status = status
	}
	if value, ok := os.LookupEnv("SINKHOLE_LOG_LEVEL"); ok {
		cfg.Logging.Level = value
	}
	if value, ok := os.LookupEnv("SINKHOLE_ACCESS_LOG"); ok {
		var enabled bool
		switch value {
		case "true":
			enabled = true
		case "false":
			enabled = false
		default:
			return fmt.Errorf("parse SINKHOLE_ACCESS_LOG: must be true or false, got %q", value)
		}
		cfg.Logging.AccessLog = &enabled
	}

	return nil
}

func commaSeparated(value string) []string {
	if strings.TrimSpace(value) == "" {
		return []string{}
	}

	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}
