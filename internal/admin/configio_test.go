package admin

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/config"
	"github.com/huntastikus/sinkhole-responder/internal/rules"
	"github.com/huntastikus/sinkhole-responder/internal/state"
	"gopkg.in/yaml.v3"
)

const testManagedBanner = "# Managed by Sinkhole Responder admin UI.\n" +
	"# Manual edits may be overwritten when settings are saved from the web UI."

func TestApplyConfigReplacesFileReloadsAndBacksUp(t *testing.T) {
	d, configPath, original := configTestSetup(t)
	newCfg := validConfig(filepath.Dir(configPath))
	newCfg.Defaults.Status = 204

	reloadCalls := 0
	var reloaded *config.Config
	err := ApplyConfig(d, configPath, newCfg, func(cfg *config.Config) error {
		reloadCalls++
		reloaded = cfg
		return nil
	}, 10)
	if err != nil {
		t.Fatalf("ApplyConfig() error = %v", err)
	}

	marshaled, err := yaml.Marshal(newCfg)
	if err != nil {
		t.Fatalf("yaml.Marshal() error = %v", err)
	}
	want := append([]byte(testManagedBanner+"\n"), marshaled...)
	got, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read replaced config: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("config bytes = %q, want %q", got, want)
	}
	if reloadCalls != 1 {
		t.Fatalf("reload calls = %d, want 1", reloadCalls)
	}
	if reloaded != newCfg {
		t.Fatalf("reload config = %p, want %p", reloaded, newCfg)
	}

	backup, err := os.ReadFile(configPath + ".bak.001")
	if err != nil {
		t.Fatalf("read config backup: %v", err)
	}
	if !bytes.Equal(backup, original) {
		t.Fatalf("backup bytes = %q, want %q", backup, original)
	}
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if gotMode := info.Mode().Perm(); gotMode != 0o600 {
		t.Fatalf("config mode = %o, want 600", gotMode)
	}
}

func TestApplyConfigRejectsInvalidConfigWithoutWriting(t *testing.T) {
	d, configPath, original := configTestSetup(t)
	newCfg := validConfig(filepath.Dir(configPath))
	newCfg.TLS.Mode = "unsupported"
	reloadCalls := 0

	err := ApplyConfig(d, configPath, newCfg, func(*config.Config) error {
		reloadCalls++
		return nil
	}, 10)
	if err == nil || !strings.Contains(err.Error(), "validate configuration") {
		t.Fatalf("ApplyConfig() error = %v, want validation error", err)
	}
	assertFileBytes(t, configPath, original)
	if reloadCalls != 0 {
		t.Fatalf("reload calls = %d, want 0", reloadCalls)
	}
	if backups, err := filepath.Glob(configPath + ".bak.*"); err != nil {
		t.Fatalf("glob backups: %v", err)
	} else if len(backups) != 0 {
		t.Fatalf("backups = %v, want none", backups)
	}
}

func TestApplyConfigRestoresOriginalWhenReloadFails(t *testing.T) {
	d, configPath, original := configTestSetup(t)
	newCfg := validConfig(filepath.Dir(configPath))
	reloadErr := errors.New("reload failed")

	err := ApplyConfig(d, configPath, newCfg, func(*config.Config) error {
		return reloadErr
	}, 10)
	if err == nil || !strings.Contains(err.Error(), "previous config restored") {
		t.Fatalf("ApplyConfig() error = %v, want restored-config error", err)
	}
	if !errors.Is(err, reloadErr) {
		t.Fatalf("ApplyConfig() error = %v, want wrapped reload error", err)
	}
	assertFileBytes(t, configPath, original)
}

func TestApplyConfigPrunesBackups(t *testing.T) {
	d, configPath, _ := configTestSetup(t)
	const keepBackups = 2

	for i := 0; i < keepBackups+2; i++ {
		newCfg := validConfig(filepath.Dir(configPath))
		newCfg.Defaults.Status = 200 + i
		if err := ApplyConfig(d, configPath, newCfg, func(*config.Config) error { return nil }, keepBackups); err != nil {
			t.Fatalf("ApplyConfig() call %d error = %v", i+1, err)
		}
	}

	backups, err := filepath.Glob(configPath + ".bak.*")
	if err != nil {
		t.Fatalf("glob backups: %v", err)
	}
	if len(backups) != keepBackups {
		t.Fatalf("backup count = %d, want %d (%v)", len(backups), keepBackups, backups)
	}
}

func TestApplyConfigRejectsUncompilableRulesWithoutWriting(t *testing.T) {
	d, configPath, original := configTestSetup(t)
	newCfg := validConfig(filepath.Dir(configPath))
	newCfg.Rules = []rules.Rule{{Name: "missing matcher"}}
	reloadCalls := 0

	err := ApplyConfig(d, configPath, newCfg, func(*config.Config) error {
		reloadCalls++
		return nil
	}, 10)
	if err == nil || !strings.Contains(err.Error(), "compile rules") {
		t.Fatalf("ApplyConfig() error = %v, want rule compilation error", err)
	}
	assertFileBytes(t, configPath, original)
	if reloadCalls != 0 {
		t.Fatalf("reload calls = %d, want 0", reloadCalls)
	}
}

func TestApplyConfigRejectsUnknownRulepackWithoutWriting(t *testing.T) {
	d, configPath, original := configTestSetup(t)
	newCfg := validConfig(filepath.Dir(configPath))
	newCfg.Rulepacks.Enabled = []string{"nope"}
	reloadCalls := 0

	err := ApplyConfig(d, configPath, newCfg, func(*config.Config) error {
		reloadCalls++
		return nil
	}, 10)
	if err == nil || !strings.Contains(err.Error(), "merge rulepacks") {
		t.Fatalf("ApplyConfig() error = %v, want rulepack merge error", err)
	}
	assertFileBytes(t, configPath, original)
	if reloadCalls != 0 {
		t.Fatalf("reload calls = %d, want 0", reloadCalls)
	}
}

func TestApplyConfigRejectsNilStateDirectory(t *testing.T) {
	_, configPath, original := configTestSetup(t)
	newCfg := validConfig(filepath.Dir(configPath))

	err := ApplyConfig(nil, configPath, newCfg, func(*config.Config) error { return nil }, 10)
	if err == nil || !strings.Contains(err.Error(), "state directory is nil") {
		t.Fatalf("ApplyConfig() error = %v, want nil state directory error", err)
	}
	assertFileBytes(t, configPath, original)
}

func configTestSetup(t *testing.T) (*state.Dir, string, []byte) {
	t.Helper()
	d, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New() error = %v", err)
	}
	configPath := d.Path("config.yaml")
	original := []byte("# original configuration\n")
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatalf("write original config: %v", err)
	}
	return d, configPath, original
}

func validConfig(configDir string) *config.Config {
	return &config.Config{
		Listen: config.ListenConfig{
			HTTP: []string{"127.0.0.1:8081"},
		},
		Management: config.MgmtConfig{
			Listen: "127.0.0.1:9090",
		},
		TLS: config.TLSConfig{
			Mode: "disabled",
		},
		Defaults: config.DefaultsConfig{
			Status:        200,
			BeaconStatus:  200,
			MediaResponse: "204",
		},
		Logging: config.LoggingConfig{
			Level: "info",
		},
		Limits: config.LimitsConfig{
			WriteTimeout: 10 * time.Second,
		},
		Admin: config.AdminConfig{
			SessionTTL: time.Hour,
		},
		ConfigDir: configDir,
	}
}

func assertFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("file bytes = %q, want %q", got, want)
	}
}
