package admin

import (
	"encoding/json"
	"fmt"
	"net/http"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/config"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/rulepacks"
)

type rulepackResponse struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	RuleCount   int    `json:"rule_count"`
	Enabled     bool   `json:"enabled"`
}

type rulepacksResponse struct {
	Packs []rulepackResponse `json:"packs"`
	Mtime jsonInt64          `json:"mtime"`
}

type rulepackToggleRequest struct {
	Name    string    `json:"name"`
	Enabled bool      `json:"enabled"`
	Mtime   jsonInt64 `json:"mtime"`
}

func (s *Server) handleRulepacks(w http.ResponseWriter, _ *http.Request) {
	cfg, mtime, err := s.configView()
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("read configuration view: %v", err))
		return
	}

	enabled := make(map[string]bool, len(cfg.Rulepacks.Enabled))
	for _, name := range cfg.Rulepacks.Enabled {
		enabled[name] = true
	}
	available := rulepacks.Available()
	packs := make([]rulepackResponse, 0, len(available))
	for _, pack := range available {
		packs = append(packs, rulepackResponse{
			Name:        pack.Name,
			Title:       pack.Title,
			Description: pack.Description,
			RuleCount:   pack.RuleCount,
			Enabled:     enabled[pack.Name],
		})
	}
	writeConfigJSON(w, http.StatusOK, rulepacksResponse{Packs: packs, Mtime: jsonInt64(mtime)})
}

func (s *Server) handleRulepackToggle(w http.ResponseWriter, r *http.Request) {
	var request rulepackToggleRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeConfigError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err))
		return
	}
	if !knownRulepack(request.Name) {
		writeConfigError(w, http.StatusBadRequest, fmt.Sprintf("unknown rulepack %q", request.Name))
		return
	}

	s.mutateConfig(w, request.Mtime, func(clone *config.Config) error {
		clone.Rulepacks.Enabled = updateEnabledRulepacks(clone.Rulepacks.Enabled, request.Name, request.Enabled)
		return nil
	}, map[string]any{
		"enabled": request.Enabled,
	})
}

func knownRulepack(name string) bool {
	for _, pack := range rulepacks.Available() {
		if pack.Name == name {
			return true
		}
	}
	return false
}

func updateEnabledRulepacks(current []string, name string, enabled bool) []string {
	updated := make([]string, 0, len(current)+1)
	seen := make(map[string]bool, len(current)+1)
	for _, existing := range current {
		if seen[existing] || (!enabled && existing == name) {
			continue
		}
		seen[existing] = true
		updated = append(updated, existing)
	}
	if enabled && !seen[name] {
		updated = append(updated, name)
	}
	return updated
}
