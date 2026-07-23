// Package state manages files stored in the application's writable state directory.
package state

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Dir is the application's writable state directory.
type Dir struct {
	Root string
}

// New creates the state directory and its required subdirectories.
func New(root string) (*Dir, error) {
	if root == "" {
		return nil, errors.New("state root is empty")
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve state root: %w", err)
	}
	rootExisted, err := pathExistsWithoutSymlink(absRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect state root: %w", err)
	}
	if err := os.MkdirAll(absRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create state root: %w", err)
	}
	if !rootExisted {
		if err := os.Chmod(absRoot, 0o700); err != nil {
			return nil, fmt.Errorf("set state root permissions: %w", err)
		}
	}

	rootInfo, err := os.Lstat(absRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect state root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("state root must not be a symlink")
	}
	if !rootInfo.IsDir() {
		return nil, errors.New("state root is not a directory")
	}
	if err := verifyWritable(absRoot); err != nil {
		return nil, fmt.Errorf("state root %q is not writable: %w", absRoot, err)
	}

	d := &Dir{Root: filepath.Clean(absRoot)}
	for _, rel := range []string{"admin", "tls", filepath.Join("tls", "uploaded"), "metrics"} {
		path, err := d.resolve(rel)
		if err != nil {
			return nil, err
		}
		if err := createStateDir(path); err != nil {
			return nil, fmt.Errorf("create state directory %q: %w", rel, err)
		}
	}

	return d, nil
}

// Path joins rel beneath Root. It returns an empty string for an invalid path.
func (d *Dir) Path(rel ...string) string {
	path, err := d.resolve(rel...)
	if err != nil {
		return ""
	}
	return path
}

// WriteAtomic replaces rel with data without exposing a partially written target.
func (d *Dir) WriteAtomic(rel string, data []byte, mode os.FileMode) error {
	target, err := d.resolve(rel)
	if err != nil {
		return fmt.Errorf("resolve state path: %w", err)
	}
	if target == d.Root {
		return errors.New("state path must name a file")
	}
	if err := d.rejectSymlinks(target, true); err != nil {
		return err
	}

	return WriteFileAtomic(target, data, mode)
}

// BackupConfig copies configPath to the next numbered backup and prunes old backups.
func (d *Dir) BackupConfig(configPath string, keep int) error {
	if keep < 0 {
		return errors.New("backup retention must not be negative")
	}

	absConfig, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	absConfig = filepath.Clean(absConfig)
	if err := d.rejectSymlinks(absConfig, false); err != nil {
		return err
	}

	info, err := os.Lstat(absConfig)
	if err != nil {
		return fmt.Errorf("inspect config: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("config path must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return errors.New("config path is not a regular file")
	}

	backups, err := numberedBackups(absConfig)
	if err != nil {
		return err
	}
	next := 1
	if len(backups) > 0 {
		next = backups[len(backups)-1].number + 1
	}
	backupPath := fmt.Sprintf("%s.bak.%03d", absConfig, next)

	data, err := os.ReadFile(absConfig)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if err := WriteFileAtomic(backupPath, data, info.Mode().Perm()); err != nil {
		return fmt.Errorf("write config backup: %w", err)
	}

	backups, err = numberedBackups(absConfig)
	if err != nil {
		return err
	}
	for len(backups) > keep {
		if err := os.Remove(backups[0].path); err != nil {
			return fmt.Errorf("prune config backup %q: %w", backups[0].path, err)
		}
		backups = backups[1:]
	}
	return nil
}

func (d *Dir) resolve(rel ...string) (string, error) {
	if d == nil || d.Root == "" {
		return "", errors.New("state directory is not initialized")
	}
	for _, part := range rel {
		if filepath.IsAbs(part) || filepath.VolumeName(part) != "" {
			return "", fmt.Errorf("absolute path %q is not allowed", part)
		}
		if hasParentComponent(part) {
			return "", fmt.Errorf("parent traversal in %q is not allowed", part)
		}
	}

	parts := append([]string{d.Root}, rel...)
	target := filepath.Clean(filepath.Join(parts...))
	if !isWithin(d.Root, target) {
		return "", fmt.Errorf("path %q escapes state root", target)
	}
	return target, nil
}

func (d *Dir) rejectSymlinks(target string, includeTarget bool) error {
	rel, err := filepath.Rel(d.Root, target)
	if err != nil {
		return fmt.Errorf("resolve path relative to state root: %w", err)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if !includeTarget && len(parts) > 0 {
		parts = parts[:len(parts)-1]
	}
	current := d.Root
	for _, part := range parts {
		if part == "." || part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) && includeTarget && current == target {
				return nil
			}
			return fmt.Errorf("inspect state path %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("state path %q contains a symlink", current)
		}
		if current != target && !info.IsDir() {
			return fmt.Errorf("state path component %q is not a directory", current)
		}
	}
	return nil
}

func createStateDir(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("path is a symlink")
		}
		if !info.IsDir() {
			return errors.New("path is not a directory")
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}

func verifyWritable(root string) error {
	file, err := os.CreateTemp(root, ".writable-*")
	if err != nil {
		return err
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Remove(name); err != nil {
		return err
	}
	return nil
}

// WriteFileAtomic replaces path with data and durably records the rename.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	target := filepath.Clean(path)
	dir := filepath.Dir(target)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()

	if _, err := io.Copy(temp, bytes.NewReader(data)); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return fmt.Errorf("set temporary file permissions: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(tempPath, target); err != nil {
		return fmt.Errorf("replace target: %w", err)
	}
	parent, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open parent directory: %w", err)
	}
	if err := parent.Sync(); err != nil {
		_ = parent.Close()
		return fmt.Errorf("sync parent directory: %w", err)
	}
	if err := parent.Close(); err != nil {
		return fmt.Errorf("close parent directory: %w", err)
	}
	return nil
}

type backup struct {
	path   string
	number int
}

// BackupInfo describes one numbered config backup.
type BackupInfo struct {
	Name    string
	Number  int
	ModTime time.Time
	Size    int64
}

// ListBackups returns the numbered backups for configPath, oldest first.
func ListBackups(configPath string) ([]BackupInfo, error) {
	backups, err := numberedBackups(configPath)
	if err != nil {
		return nil, err
	}
	infos := make([]BackupInfo, 0, len(backups))
	for _, backup := range backups {
		info, err := os.Lstat(backup.path)
		if err != nil {
			return nil, fmt.Errorf("inspect backup %q: %w", backup.path, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("inspect backup %q: not a regular file", backup.path)
		}
		infos = append(infos, BackupInfo{
			Name:    filepath.Base(backup.path),
			Number:  backup.number,
			ModTime: info.ModTime(),
			Size:    info.Size(),
		})
	}
	return infos, nil
}

func numberedBackups(configPath string) ([]backup, error) {
	dir := filepath.Dir(configPath)
	prefix := filepath.Base(configPath) + ".bak."
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("list config backups: %w", err)
	}

	backups := make([]backup, 0)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, prefix) {
			continue
		}
		suffix := strings.TrimPrefix(name, prefix)
		if suffix == "" || strings.IndexFunc(suffix, func(r rune) bool { return !unicode.IsDigit(r) }) >= 0 {
			continue
		}
		number, err := strconv.Atoi(suffix)
		if err != nil {
			continue
		}
		backups = append(backups, backup{path: filepath.Join(dir, name), number: number})
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].number < backups[j].number })
	return backups, nil
}

func hasParentComponent(path string) bool {
	for _, part := range strings.FieldsFunc(path, func(r rune) bool {
		return r == '/' || r == '\\'
	}) {
		if part == ".." {
			return true
		}
	}
	return false
}

func isWithin(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func pathExistsWithoutSymlink(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("path is a symlink")
	}
	return true, nil
}
