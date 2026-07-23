package admin

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/config"
	"github.com/huntastikus/sinkhole-responder/internal/state"
)

type backupInfoResponse struct {
	Name   string    `json:"name"`
	Number int       `json:"number"`
	Mtime  time.Time `json:"mtime"`
	Size   int64     `json:"size"`
}

type backupsResponse struct {
	Backups []backupInfoResponse `json:"backups"`
	Mtime   jsonInt64            `json:"mtime"`
}

type backupRestoreRequest struct {
	Name  string    `json:"name"`
	Mtime jsonInt64 `json:"mtime"`
}

func (s *Server) handleBackupsList(w http.ResponseWriter, _ *http.Request) {
	if s.deps.ConfigPath == "" {
		writeConfigError(w, http.StatusConflict, "config file path is not configured; backups are unavailable")
		return
	}
	backups, err := state.ListBackups(s.deps.ConfigPath)
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, err.Error())
		return
	}
	mtime, err := configFileMtime(s.deps.ConfigPath)
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, err.Error())
		return
	}
	response := backupsResponse{
		Backups: make([]backupInfoResponse, len(backups)),
		Mtime:   jsonInt64(mtime),
	}
	for i, backup := range backups {
		response.Backups[i] = backupInfoResponse{
			Name:   backup.Name,
			Number: backup.Number,
			Mtime:  backup.ModTime,
			Size:   backup.Size,
		}
	}
	writeConfigJSON(w, http.StatusOK, response)
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	var request backupRestoreRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeConfigError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err))
		return
	}

	s.configWriteMu.Lock()
	defer s.configWriteMu.Unlock()

	if s.deps.ConfigPath == "" {
		writeConfigError(w, http.StatusConflict, "config file path is not configured; backups are unavailable")
		return
	}
	configName := filepath.Base(s.deps.ConfigPath)
	if request.Name != filepath.Base(request.Name) || !strings.HasPrefix(request.Name, configName+".bak.") {
		writeConfigError(w, http.StatusBadRequest, "invalid backup name")
		return
	}
	backups, err := state.ListBackups(s.deps.ConfigPath)
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, err.Error())
		return
	}
	found := false
	for _, backup := range backups {
		if backup.Name == request.Name {
			found = true
			break
		}
	}
	if !found {
		writeConfigError(w, http.StatusBadRequest, "backup not found")
		return
	}
	currentMtime, err := configFileMtime(s.deps.ConfigPath)
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !s.configMtimeMatches(w, request.Mtime, currentMtime) {
		return
	}

	raw, err := os.ReadFile(filepath.Join(filepath.Dir(s.deps.ConfigPath), request.Name))
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("read backup: %v", err))
		return
	}
	replacement, err := config.ParseBytes(raw, filepath.Dir(s.deps.ConfigPath))
	if err != nil {
		writeConfigError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := ApplyConfig(s.deps.State, s.deps.ConfigPath, replacement, s.deps.Reload, keepConfigBackups); err != nil {
		writeConfigError(w, http.StatusBadRequest, err.Error())
		return
	}
	newMtime, err := configFileMtime(s.deps.ConfigPath)
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeConfigJSON(w, http.StatusOK, map[string]any{
		"mtime":            jsonInt64(newMtime),
		"restart_required": s.deps.RestartPending != nil && s.deps.RestartPending(),
	})
}

func (s *Server) handleBackupArchive(w http.ResponseWriter, _ *http.Request) {
	if s.deps.ConfigPath == "" || s.deps.State == nil {
		writeConfigError(w, http.StatusConflict, "config file path and state directory are required for backup archives")
		return
	}
	backups, err := state.ListBackups(s.deps.ConfigPath)
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, err.Error())
		return
	}

	filename := "sinkhole-backup-" + time.Now().UTC().Format("20060102-150405") + ".tar.gz"
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	gzipWriter := gzip.NewWriter(w)
	tarWriter := tar.NewWriter(gzipWriter)

	writeErr := addArchiveFile(tarWriter, s.deps.ConfigPath, filepath.Base(s.deps.ConfigPath))
	for _, backup := range backups {
		if writeErr != nil {
			break
		}
		path := filepath.Join(filepath.Dir(s.deps.ConfigPath), backup.Name)
		writeErr = addArchiveFile(tarWriter, path, backup.Name)
	}
	if writeErr == nil {
		tlsRoot := s.deps.State.Path("tls")
		writeErr = filepath.WalkDir(tlsRoot, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if path == tlsRoot || entry.IsDir() {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(tlsRoot, path)
			if err != nil {
				return err
			}
			return addArchiveFile(tarWriter, path, filepath.ToSlash(filepath.Join("tls", rel)))
		})
	}
	if err := tarWriter.Close(); writeErr == nil {
		writeErr = err
	}
	if err := gzipWriter.Close(); writeErr == nil {
		writeErr = err
	}
	if writeErr != nil {
		s.logger.Error("write backup archive", "error", writeErr)
	}
}

func addArchiveFile(writer *tar.Writer, path, name string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("archive source %q is not a regular file", path)
	}
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = filepath.ToSlash(name)
	if err := writer.WriteHeader(header); err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(writer, file)
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
