package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type passwordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	if !s.allowLogin(r.RemoteAddr) {
		writeConfigError(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	var request passwordChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeConfigError(w, http.StatusBadRequest, "decode request")
		return
	}
	credential, present, err := s.loadCredential()
	if err != nil {
		s.internalError(w, "load admin credential", err)
		return
	}
	if !present {
		s.internalError(w, "load admin credential", fmt.Errorf("admin credential is unavailable"))
		return
	}
	if !credential.Verify(request.CurrentPassword) {
		writeConfigError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	updated, err := HashPassword(request.NewPassword)
	if err != nil {
		writeConfigError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := RotateSessionKey(s.deps.State); err != nil {
		s.internalError(w, "rotate admin sessions", err)
		return
	}
	if err := SaveCredential(s.deps.State, updated); err != nil {
		s.internalError(w, "save admin credential", err)
		return
	}
	if err := s.reloadSessionKey(); err != nil {
		s.internalError(w, "reload session key", err)
		return
	}
	if !s.issueAuthCookies(w) {
		return
	}
	writeConfigJSON(w, http.StatusOK, map[string]any{"ok": true})
}
