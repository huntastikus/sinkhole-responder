package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/config"
	"gopkg.in/yaml.v3"
)

const (
	configImportBodyLimit = 1 << 20
	keepConfigBackups     = 10
)

type configResponse struct {
	Config map[string]any `json:"config"`
	Mtime  jsonInt64      `json:"mtime"`
	Path   string         `json:"path"`
}

type rawConfigResponse struct {
	Raw   string    `json:"raw"`
	Mtime jsonInt64 `json:"mtime"`
	Path  string    `json:"path"`
}

type rawConfigRequest struct {
	Raw   string    `json:"raw"`
	Mtime jsonInt64 `json:"mtime"`
}

type configRequest struct {
	Config map[string]any `json:"config"`
	Mtime  jsonInt64      `json:"mtime"`
}

func (s *Server) handleConfig(w http.ResponseWriter, _ *http.Request) {
	cfg, mtime, err := s.configView()
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("read configuration view: %v", err))
		return
	}

	yamlConfig, err := yaml.Marshal(cfg)
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("marshal configuration: %v", err))
		return
	}
	var configMap map[string]any
	if err := yaml.Unmarshal(yamlConfig, &configMap); err != nil {
		writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("convert configuration: %v", err))
		return
	}
	writeConfigJSON(w, http.StatusOK, configResponse{Config: configMap, Mtime: jsonInt64(mtime), Path: s.deps.ConfigPath})
}

func (s *Server) handleRawConfig(w http.ResponseWriter, _ *http.Request) {
	raw, mtime, err := s.readRawConfig()
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeConfigJSON(w, http.StatusOK, rawConfigResponse{Raw: string(raw), Mtime: jsonInt64(mtime), Path: s.deps.ConfigPath})
}

func (s *Server) handleConfigExport(w http.ResponseWriter, _ *http.Request) {
	raw, _, err := s.readRawConfig()
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="sinkhole-config.yaml"`)
	_, _ = w.Write(raw)
}

func (s *Server) handleConfigImport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, configImportBodyLimit)

	s.configWriteMu.Lock()
	defer s.configWriteMu.Unlock()

	if s.deps.ConfigPath == "" {
		writeConfigError(w, http.StatusConflict, "config file path is not configured; live write-back is unavailable")
		return
	}
	if err := r.ParseMultipartForm(configImportBodyLimit); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeConfigError(w, http.StatusRequestEntityTooLarge, "file too large (max 1 MiB)")
			return
		}
		writeConfigError(w, http.StatusBadRequest, "invalid multipart upload")
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		writeConfigError(w, http.StatusBadRequest, "configuration file is required")
		return
	}
	defer file.Close()
	uploaded, err := io.ReadAll(file)
	if err != nil {
		writeConfigError(w, http.StatusBadRequest, fmt.Sprintf("read configuration file: %v", err))
		return
	}

	current := s.deps.Cfg()
	newCfg, err := config.ParseBytes(uploaded, current.ConfigDir)
	if err != nil {
		writeConfigError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := ApplyConfig(s.deps.State, s.deps.ConfigPath, newCfg, s.deps.Reload, keepConfigBackups); err != nil {
		writeConfigError(w, http.StatusBadRequest, err.Error())
		return
	}

	newMtime, err := configFileMtime(s.deps.ConfigPath)
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeConfigJSON(w, http.StatusOK, map[string]jsonInt64{"mtime": jsonInt64(newMtime)})
}

func (s *Server) handleConfigWrite(w http.ResponseWriter, r *http.Request) {
	var request configRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeConfigError(w, http.StatusBadRequest, fmt.Sprintf("read request: %v", err))
		return
	}
	if err := json.Unmarshal(body, &request); err != nil {
		writeConfigError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err))
		return
	}
	s.mutateConfig(w, request.Mtime, func(clone *config.Config) error {
		yamlConfig, err := yaml.Marshal(request.Config)
		if err != nil {
			return fmt.Errorf("marshal configuration: %w", err)
		}
		replacement, err := config.ParseBytes(yamlConfig, clone.ConfigDir)
		if err != nil {
			return err
		}
		*clone = *replacement
		return nil
	})
}

func (s *Server) handleRawConfigWrite(w http.ResponseWriter, r *http.Request) {
	var request rawConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeConfigError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err))
		return
	}
	s.mutateConfig(w, request.Mtime, func(clone *config.Config) error {
		replacement, err := config.ParseBytes([]byte(request.Raw), clone.ConfigDir)
		if err != nil {
			return err
		}
		*clone = *replacement
		return nil
	})
}

func (s *Server) mutateConfig(w http.ResponseWriter, mtime jsonInt64, mutate func(clone *config.Config) error, responseFields ...map[string]any) {
	s.configWriteMu.Lock()
	defer s.configWriteMu.Unlock()

	if s.deps.ConfigPath == "" {
		writeConfigError(w, http.StatusConflict, "config file path is not configured; live write-back is unavailable")
		return
	}
	current, currentMtime, err := s.configView()
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("read configuration view: %v", err))
		return
	}
	if !s.configMtimeMatches(w, mtime, currentMtime) {
		return
	}
	snapshot, err := config.MarshalConfig(current)
	if err != nil {
		writeConfigError(w, http.StatusBadRequest, err.Error())
		return
	}
	clone, err := config.ParseBytes(snapshot, current.ConfigDir)
	if err != nil {
		writeConfigError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := mutate(clone); err != nil {
		writeConfigError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := ApplyConfig(s.deps.State, s.deps.ConfigPath, clone, s.deps.Reload, keepConfigBackups); err != nil {
		writeConfigError(w, http.StatusBadRequest, err.Error())
		return
	}

	newMtime, err := configFileMtime(s.deps.ConfigPath)
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, err.Error())
		return
	}
	response := map[string]any{"mtime": jsonInt64(newMtime)}
	// The reload ran synchronously above, so the restart-pending flag now reflects
	// this save. Surface it so the GUI can flag a needed restart immediately.
	response["restart_required"] = s.deps.RestartPending != nil && s.deps.RestartPending()
	if len(responseFields) > 0 {
		for key, value := range responseFields[0] {
			response[key] = value
		}
	}
	writeConfigJSON(w, http.StatusOK, response)
}

func (s *Server) configMtimeMatches(w http.ResponseWriter, requested jsonInt64, current int64) bool {
	if current != int64(requested) {
		writeConfigJSON(w, http.StatusConflict, map[string]any{
			"error":         "config file changed on disk since it was loaded; reload before saving",
			"current_mtime": jsonInt64(current),
		})
		return false
	}
	return true
}

func (s *Server) configView() (*config.Config, int64, error) {
	if s.deps.ConfigPath == "" {
		return s.deps.Cfg(), 0, nil
	}
	file, err := os.Open(s.deps.ConfigPath)
	if err != nil {
		return nil, 0, fmt.Errorf("open config file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("stat config file: %w", err)
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, 0, fmt.Errorf("read config file: %w", err)
	}
	cfg, err := config.ParseBytes(raw, filepath.Dir(s.deps.ConfigPath))
	if err != nil {
		return nil, 0, fmt.Errorf("parse config file: %w", err)
	}
	return cfg, info.ModTime().UnixNano(), nil
}

func (s *Server) readRawConfig() ([]byte, int64, error) {
	if s.deps.ConfigPath != "" {
		file, err := os.Open(s.deps.ConfigPath)
		if err == nil {
			defer file.Close()
			info, err := file.Stat()
			if err != nil {
				return nil, 0, fmt.Errorf("stat config file: %w", err)
			}
			raw, err := io.ReadAll(file)
			if err != nil {
				return nil, 0, fmt.Errorf("read config file: %w", err)
			}
			return raw, info.ModTime().UnixNano(), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, 0, fmt.Errorf("open config file: %w", err)
		}
	}

	raw, err := config.MarshalConfig(s.deps.Cfg())
	if err != nil {
		return nil, 0, err
	}
	return raw, 0, nil
}

func configFileMtime(path string) (int64, error) {
	if path == "" {
		return 0, nil
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("stat config file: %w", err)
	}
	return info.ModTime().UnixNano(), nil
}

func writeConfigError(w http.ResponseWriter, status int, message string) {
	writeConfigJSON(w, status, map[string]string{"error": message})
}

func writeConfigJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
