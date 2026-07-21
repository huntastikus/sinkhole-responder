package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExampleConfigParsesAndValidates(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	data, err := os.ReadFile(filepath.Join(repoRoot, "config.example.yaml"))
	if err != nil {
		t.Fatalf("read config.example.yaml: %v", err)
	}

	cfg, err := ParseBytes(data, repoRoot)
	if err != nil {
		t.Fatalf("ParseBytes(config.example.yaml) error = %v", err)
	}
	if !cfg.Admin.Enabled {
		t.Fatal("config.example.yaml admin.enabled = false, want true")
	}
}
