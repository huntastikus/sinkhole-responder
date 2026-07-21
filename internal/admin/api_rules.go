package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/assets"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/config"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/rules"
	"gopkg.in/yaml.v3"
)

const rulesPreviewBodyLimit = 2 * 1024

type rulesResponse struct {
	Rules []any     `json:"rules"`
	Mtime jsonInt64 `json:"mtime"`
}

type rulesWriteRequest struct {
	Rules []map[string]any `json:"rules"`
	Mtime jsonInt64        `json:"mtime"`
}

type rulesReorderRequest struct {
	Order []int     `json:"order"`
	Mtime jsonInt64 `json:"mtime"`
}

type rulesPreviewRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Host    string            `json:"host"`
	Headers map[string]string `json:"headers"`
}

type rulesPreviewResponse struct {
	MatchedRuleName string `json:"matched_rule_name"`
	Kind            string `json:"kind"`
	Status          int    `json:"status"`
	ContentType     string `json:"content_type"`
	BodyPreview     string `json:"body_preview"`
	BodyTruncated   bool   `json:"body_truncated"`
	DelayMS         int64  `json:"delay_ms"`
}

func (s *Server) handleRules(w http.ResponseWriter, _ *http.Request) {
	cfg, mtime, err := s.configView()
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("read configuration view: %v", err))
		return
	}

	yamlRules, err := yaml.Marshal(cfg.Rules)
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("marshal rules: %v", err))
		return
	}
	out := make([]any, 0)
	decoder := yaml.NewDecoder(bytes.NewReader(yamlRules))
	decoder.KnownFields(true)
	if err := decoder.Decode(&out); err != nil {
		writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("convert rules: %v", err))
		return
	}
	writeConfigJSON(w, http.StatusOK, rulesResponse{Rules: out, Mtime: jsonInt64(mtime)})
}

func (s *Server) handleRulesWrite(w http.ResponseWriter, r *http.Request) {
	var request rulesWriteRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeConfigError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err))
		return
	}
	yamlRules, _ := yaml.Marshal(request.Rules)
	var newRules []rules.Rule
	decoder := yaml.NewDecoder(bytes.NewReader(yamlRules))
	decoder.KnownFields(true)
	if err := decoder.Decode(&newRules); err != nil {
		writeConfigError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.mutateConfig(w, request.Mtime, func(clone *config.Config) error {
		clone.Rules = newRules
		return nil
	})
}

func (s *Server) handleRulesReorder(w http.ResponseWriter, r *http.Request) {
	var request rulesReorderRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeConfigError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err))
		return
	}
	s.mutateConfig(w, request.Mtime, func(clone *config.Config) error {
		if !validRuleOrder(request.Order, len(clone.Rules)) {
			return fmt.Errorf("order must be a permutation of the current rule indices")
		}
		reordered := make([]rules.Rule, len(request.Order))
		for i, index := range request.Order {
			reordered[i] = clone.Rules[index]
		}
		clone.Rules = reordered
		return nil
	})
}

func (s *Server) handleRulesPreview(w http.ResponseWriter, r *http.Request) {
	var preview rulesPreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&preview); err != nil {
		writeConfigError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err))
		return
	}
	host := preview.Host
	cfg := s.deps.Cfg()
	decision, errorStatus, err := previewSelect(cfg, preview.Method, preview.Path, host, preview.Headers)
	if err != nil {
		writeConfigError(w, errorStatus, err.Error())
		return
	}
	bodyPreview := decision.Body
	truncated := len(bodyPreview) > rulesPreviewBodyLimit
	if truncated {
		bodyPreview = bodyPreview[:rulesPreviewBodyLimit]
	}
	writeConfigJSON(w, http.StatusOK, rulesPreviewResponse{
		MatchedRuleName: decision.RuleName,
		Kind:            string(decision.Kind),
		Status:          decision.Status,
		ContentType:     decision.ContentType,
		BodyPreview:     string(bodyPreview),
		BodyTruncated:   truncated,
		DelayMS:         decision.Delay.Milliseconds(),
	})
}

func (s *Server) handleAssets(w http.ResponseWriter, _ *http.Request) {
	writeConfigJSON(w, http.StatusOK, map[string]any{"assets": assets.Names()})
}

func validRuleOrder(order []int, ruleCount int) bool {
	if len(order) != ruleCount {
		return false
	}
	seen := make([]bool, ruleCount)
	for _, index := range order {
		if index < 0 || index >= ruleCount || seen[index] {
			return false
		}
		seen[index] = true
	}
	return true
}
