package state

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
)

func TestWriteAtomicCreatesAndReplacesFile(t *testing.T) {
	d, err := New(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	oldData := bytes.Repeat([]byte("old-content\n"), 4096)
	newData := bytes.Repeat([]byte("new-content\n"), 4096)
	const rel = "admin/value.txt"
	if err := d.WriteAtomic(rel, oldData, 0o600); err != nil {
		t.Fatalf("first WriteAtomic() error = %v", err)
	}

	ready := make(chan struct{})
	stop := make(chan struct{})
	readErr := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		signaled := false
		for {
			data, err := os.ReadFile(d.Path(rel))
			if err != nil {
				select {
				case readErr <- fmt.Errorf("read target: %w", err):
				default:
				}
				return
			}
			if !bytes.Equal(data, oldData) && !bytes.Equal(data, newData) {
				select {
				case readErr <- fmt.Errorf("observed partial content of %d bytes", len(data)):
				default:
				}
				return
			}
			if !signaled {
				close(ready)
				signaled = true
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()

	select {
	case <-ready:
	case err := <-readErr:
		t.Fatalf("reader failed before replacement: %v", err)
	}
	if err := d.WriteAtomic(rel, newData, 0o640); err != nil {
		close(stop)
		wg.Wait()
		t.Fatalf("second WriteAtomic() error = %v", err)
	}
	close(stop)
	wg.Wait()
	select {
	case err := <-readErr:
		t.Fatal(err)
	default:
	}

	got, err := os.ReadFile(d.Path(rel))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(got, newData) {
		t.Fatal("target does not contain the second write")
	}
	info, err := os.Stat(d.Path(rel))
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if gotMode := info.Mode().Perm(); gotMode != 0o640 {
		t.Fatalf("mode = %04o, want 0640", gotMode)
	}
}

func TestWriteFileAtomicCreatesFileWithRequestedMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials")
	if err := WriteFileAtomic(path, []byte("secret"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != "secret" {
		t.Fatalf("content = %q, want secret", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %04o, want 0600", got)
	}
}

func TestRejectsParentTraversal(t *testing.T) {
	d, err := New(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	for _, rel := range []string{"../escape", "admin/../escape", filepath.Join("..", "escape")} {
		if got := d.Path(rel); got != "" {
			t.Errorf("Path(%q) = %q, want empty string", rel, got)
		}
		if err := d.WriteAtomic(rel, []byte("escape"), 0o600); err == nil {
			t.Errorf("WriteAtomic(%q) error = nil, want traversal error", rel)
		}
	}
	if got := d.Path(string(filepath.Separator) + "tmp" + string(filepath.Separator) + "escape"); got != "" {
		t.Errorf("Path(absolute) = %q, want empty string", got)
	}
}

func TestBackupConfigRotatesAndPrunes(t *testing.T) {
	d, err := New(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	configPath := d.Path("config.yaml")

	for n := 1; n <= 4; n++ {
		content := fmt.Sprintf("version: %d\n", n)
		if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile(version %d) error = %v", n, err)
		}
		if err := d.BackupConfig(configPath, 2); err != nil {
			t.Fatalf("BackupConfig(version %d) error = %v", n, err)
		}
	}

	backups, err := filepath.Glob(configPath + ".bak.*")
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	sort.Strings(backups)
	wantNames := []string{configPath + ".bak.003", configPath + ".bak.004"}
	if strings.Join(backups, "\n") != strings.Join(wantNames, "\n") {
		t.Fatalf("backups = %q, want %q", backups, wantNames)
	}
	for i, path := range backups {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%q) error = %v", path, err)
		}
		want := fmt.Sprintf("version: %d\n", i+3)
		if string(got) != want {
			t.Errorf("%s content = %q, want %q", filepath.Base(path), got, want)
		}
	}
}

func TestBackupConfigAllowsConfigOutsideStateRoot(t *testing.T) {
	base := t.TempDir()
	d, err := New(filepath.Join(base, "state"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	configDir := filepath.Join(base, "etc")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	configPath := filepath.Join(configDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("listen: {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if err := d.BackupConfig(configPath, 1); err != nil {
		t.Fatalf("BackupConfig() error = %v", err)
	}
	backupPath := configPath + ".bak.001"
	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", backupPath, err)
	}
	if string(data) != "listen: {}\n" {
		t.Fatalf("backup content = %q", data)
	}
}

func TestNewRejectsReadOnlyRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0o500); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })

	if _, err := New(root); err == nil {
		t.Fatal("New() error = nil, want read-only root error")
	}
}

func TestDoesNotFollowSymlinksOutsideRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on Windows")
	}

	root := filepath.Join(t.TempDir(), "state")
	outside := t.TempDir()
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "admin")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if _, err := New(root); err == nil {
		t.Fatal("New() error = nil, want symlink error")
	}

	root = filepath.Join(t.TempDir(), "state")
	d, err := New(root)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	uploaded := d.Path("tls", "uploaded")
	if err := os.Remove(uploaded); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if err := os.Symlink(outside, uploaded); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if err := d.WriteAtomic("tls/uploaded/escape", []byte("escape"), 0o600); err == nil {
		t.Fatal("WriteAtomic() error = nil, want symlink escape error")
	}
	if _, err := os.Stat(filepath.Join(outside, "escape")); !os.IsNotExist(err) {
		t.Fatalf("outside file exists or stat failed unexpectedly: %v", err)
	}
}
