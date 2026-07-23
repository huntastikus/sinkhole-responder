package admin

import (
	"net/http"
	"time"
)

type apiTokenResponse struct {
	Present   bool       `json:"present"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	Token     string     `json:"token,omitempty"`
}

func (s *Server) handleAPITokenStatus(w http.ResponseWriter, _ *http.Request) {
	token, present, err := LoadAPIToken(s.deps.State)
	if err != nil {
		s.internalError(w, "load API token", err)
		return
	}
	response := apiTokenResponse{Present: present}
	if present {
		response.CreatedAt = &token.CreatedAt
	}
	writeConfigJSON(w, http.StatusOK, response)
}

func (s *Server) handleAPITokenGenerate(w http.ResponseWriter, _ *http.Request) {
	plaintext, token, err := GenerateAPIToken()
	if err != nil {
		s.internalError(w, "generate API token", err)
		return
	}
	if err := SaveAPIToken(s.deps.State, token); err != nil {
		s.internalError(w, "save API token", err)
		return
	}
	writeConfigJSON(w, http.StatusOK, apiTokenResponse{
		Present:   true,
		CreatedAt: &token.CreatedAt,
		Token:     plaintext,
	})
}

func (s *Server) handleAPITokenDelete(w http.ResponseWriter, _ *http.Request) {
	if err := DeleteAPIToken(s.deps.State); err != nil {
		s.internalError(w, "delete API token", err)
		return
	}
	writeConfigJSON(w, http.StatusOK, map[string]any{"ok": true})
}
