package admin

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/huntastikus/sinkhole-responder/internal/state"
)

type backupsAPIResponse struct {
	Backups []struct {
		Name   string `json:"name"`
		Number int    `json:"number"`
		Mtime  string `json:"mtime"`
		Size   int64  `json:"size"`
	} `json:"backups"`
	Mtime string `json:"mtime"`
}

func TestBackupsAPIListsConfigBackups(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	for range 2 {
		if err := fixture.server.deps.State.BackupConfig(fixture.configPath, keepConfigBackups); err != nil {
			t.Fatalf("BackupConfig: %v", err)
		}
	}

	response := performJSONRequest(t, fixture.server, http.MethodGet, "/api/config/backups", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	var body backupsAPIResponse
	decodeJSON(t, response, &body)
	if len(body.Backups) != 2 || body.Backups[0].Number != 1 || body.Backups[1].Number != 2 {
		t.Fatalf("backups = %#v, want numbered entries 1 and 2", body.Backups)
	}
	if body.Mtime != strconv.FormatInt(fileMtime(t, fixture.configPath), 10) {
		t.Errorf("mtime = %q, want current config mtime", body.Mtime)
	}
}

func TestBackupsAPIRestoresSelectedBackup(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	if err := fixture.server.deps.State.BackupConfig(fixture.configPath, keepConfigBackups); err != nil {
		t.Fatalf("BackupConfig: %v", err)
	}
	changed := strings.Replace(configAPITestYAML, "level: info", "level: debug", 1)
	if err := state.WriteFileAtomic(fixture.configPath, []byte(changed), 0o600); err != nil {
		t.Fatalf("write changed config: %v", err)
	}
	mtime := fileMtime(t, fixture.configPath)
	request, err := json.Marshal(map[string]any{
		"name":  "config.yaml.bak.001",
		"mtime": strconv.FormatInt(mtime, 10),
	})
	if err != nil {
		t.Fatal(err)
	}

	response := performJSONRequest(t, fixture.server, http.MethodPost, "/api/config/backups/restore", request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	written, err := os.ReadFile(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(written), "level: info") {
		t.Fatalf("restored config = %q, want original info level", written)
	}
	if fixture.reloadCalls != 1 {
		t.Fatalf("reload calls = %d, want 1", fixture.reloadCalls)
	}
	backups, err := state.ListBackups(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 2 {
		t.Fatalf("backup count after restore = %d, want 2", len(backups))
	}
}

func TestBackupsAPIRestoreRejectsInvalidSelection(t *testing.T) {
	for _, name := range []string{"../evil", "config.yaml.bak.999"} {
		t.Run(name, func(t *testing.T) {
			fixture := newConfigAPIFixture(t)
			body, err := json.Marshal(map[string]any{
				"name":  name,
				"mtime": strconv.FormatInt(fileMtime(t, fixture.configPath), 10),
			})
			if err != nil {
				t.Fatal(err)
			}
			response := performJSONRequest(t, fixture.server, http.MethodPost, "/api/config/backups/restore", body)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusBadRequest, response.Body.String())
			}
		})
	}
}

func TestBackupsAPIRestoreRejectsStaleMtime(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	if err := fixture.server.deps.State.BackupConfig(fixture.configPath, keepConfigBackups); err != nil {
		t.Fatalf("BackupConfig: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"name":  "config.yaml.bak.001",
		"mtime": strconv.FormatInt(fileMtime(t, fixture.configPath)-1, 10),
	})
	if err != nil {
		t.Fatal(err)
	}
	response := performJSONRequest(t, fixture.server, http.MethodPost, "/api/config/backups/restore", body)
	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusConflict, response.Body.String())
	}
}

func TestBackupArchiveContainsOnlyConfigBackupsAndTLS(t *testing.T) {
	fixture := newConfigAPIFixture(t)
	if err := fixture.server.deps.State.BackupConfig(fixture.configPath, keepConfigBackups); err != nil {
		t.Fatalf("BackupConfig: %v", err)
	}
	if err := os.WriteFile(fixture.server.deps.State.Path("tls", "ca.key"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.server.deps.State.Path("metrics", "state.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	response := performJSONRequest(t, fixture.server, http.MethodGet, "/api/backup/archive", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	if got := response.Header().Get("Content-Disposition"); !strings.HasPrefix(got, `attachment; filename="sinkhole-backup-`) {
		t.Errorf("Content-Disposition = %q", got)
	}
	gzipReader, err := gzip.NewReader(response.Body)
	if err != nil {
		t.Fatalf("open gzip: %v", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	names := make(map[string]bool)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		names[filepath.ToSlash(header.Name)] = true
	}
	for _, name := range []string{"config.yaml", "config.yaml.bak.001", "tls/ca.key"} {
		if !names[name] {
			t.Errorf("archive missing %q: %v", name, names)
		}
	}
	if names["metrics/state.json"] {
		t.Errorf("archive unexpectedly contains metrics state: %v", names)
	}
}
