package admin

import (
	"errors"
	"fmt"
	"os"

	"github.com/huntastikus/sinkhole-responder/internal/config"
	"github.com/huntastikus/sinkhole-responder/internal/rulepacks"
	"github.com/huntastikus/sinkhole-responder/internal/rules"
	"github.com/huntastikus/sinkhole-responder/internal/state"
)

// ApplyConfig validates, persists, and reloads a proposed configuration.
func ApplyConfig(d *state.Dir, configPath string, newCfg *config.Config, reload func(*config.Config) error, keepBackups int) error {
	if err := newCfg.Validate(); err != nil {
		return fmt.Errorf("validate configuration: %w", err)
	}
	if _, err := rules.Compile(newCfg.Rules, newCfg.ConfigDir); err != nil {
		return fmt.Errorf("compile rules: %w", err)
	}
	if _, err := rulepacks.Merge(newCfg.Rules, newCfg.Rulepacks.Enabled); err != nil {
		return fmt.Errorf("merge rulepacks: %w", err)
	}

	prevBytes, err := os.ReadFile(configPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read current configuration: %w", err)
		}
		prevBytes = nil
	}
	if d == nil {
		return errors.New("state directory is nil")
	}
	if err := d.BackupConfig(configPath, keepBackups); err != nil {
		return fmt.Errorf("backup current configuration: %w", err)
	}

	data, err := config.MarshalConfig(newCfg)
	if err != nil {
		return fmt.Errorf("marshal configuration: %w", err)
	}
	if err := state.WriteFileAtomic(configPath, data, 0o600); err != nil {
		return fmt.Errorf("write configuration: %w", err)
	}

	if err := reload(newCfg); err != nil {
		if prevBytes == nil {
			return fmt.Errorf("reload new configuration (no previous config to restore): %w", err)
		}
		if restoreErr := state.WriteFileAtomic(configPath, prevBytes, 0o600); restoreErr != nil {
			return fmt.Errorf("reload new configuration: %w; restore previous configuration: %w", err, restoreErr)
		}
		return fmt.Errorf("reload new configuration (previous config restored): %w", err)
	}

	return nil
}
