package admin

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/config"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/respond"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/rulepacks"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/rules"
)

type testDomainRequest struct {
	Domain string `json:"domain"`
	Path   string `json:"path"`
	Method string `json:"method"`
}

type testDomainResponse struct {
	MatchedRuleName string `json:"matched_rule_name"`
	Kind            string `json:"kind"`
	Status          int    `json:"status"`
	ContentType     string `json:"content_type"`
	BodyPreview     string `json:"body_preview"`
	BodyTruncated   bool   `json:"body_truncated"`
	WouldBlock      bool   `json:"would_block"`
}

type aghConfigResponse struct {
	IP      string   `json:"ip"`
	Steps   []string `json:"steps"`
	YAML    string   `json:"yaml"`
	Warning string   `json:"warning"`
}

func (s *Server) handleTestDomain(w http.ResponseWriter, r *http.Request) {
	var input testDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeConfigError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err))
		return
	}
	cfg := s.deps.Cfg()
	decision, errorStatus, err := previewSelect(cfg, input.Method, input.Path, input.Domain, nil)
	if err != nil {
		writeConfigError(w, errorStatus, err.Error())
		return
	}
	bodyPreview := decision.Body
	truncated := len(bodyPreview) > rulesPreviewBodyLimit
	if truncated {
		bodyPreview = bodyPreview[:rulesPreviewBodyLimit]
	}

	writeConfigJSON(w, http.StatusOK, testDomainResponse{
		MatchedRuleName: decision.RuleName,
		Kind:            string(decision.Kind),
		Status:          decision.Status,
		ContentType:     decision.ContentType,
		BodyPreview:     string(bodyPreview),
		BodyTruncated:   truncated,
		WouldBlock:      true,
	})
}

func previewSelect(cfg *config.Config, method, path, host string, headers map[string]string) (respond.Decision, int, error) {
	if method == "" {
		method = http.MethodGet
	}
	if path == "" {
		path = "/"
	}
	request, err := http.NewRequest(method, path, nil)
	if err != nil {
		return respond.Decision{}, http.StatusBadRequest, err
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	if host == "" {
		host = request.Header.Get("Host")
	}
	request.Host = host

	merged, err := rulepacks.Merge(cfg.Rules, cfg.Rulepacks.Enabled)
	if err != nil {
		return respond.Decision{}, http.StatusInternalServerError, err
	}
	engine, err := rules.Compile(merged, cfg.ConfigDir)
	if err != nil {
		return respond.Decision{}, http.StatusInternalServerError, err
	}
	return respond.Select(request, engine, cfg), 0, nil
}

func (s *Server) handleAGHConfig(w http.ResponseWriter, r *http.Request) {
	parsedIP := net.ParseIP(r.URL.Query().Get("ip"))
	if parsedIP == nil {
		writeConfigError(w, http.StatusBadRequest, "invalid ip")
		return
	}

	ip := parsedIP.String()
	blockingIPv4 := "\"\""
	blockingIPv6 := "\"\""
	addressStep := fmt.Sprintf("(IPv6 responder) set **Blocking IPv6** = `%s`", ip)
	if parsedIP.To4() != nil {
		blockingIPv4 = ip
		addressStep = fmt.Sprintf("Set **Blocking IPv4** = `%s` (for an IPv4 responder)", ip)
	} else {
		blockingIPv6 = ip
	}

	writeConfigJSON(w, http.StatusOK, aghConfigResponse{
		IP: ip,
		Steps: []string{
			"AdGuard Home → Settings → DNS settings → Blocking mode → select **Custom IP**",
			addressStep,
			"Save",
			"Ensure your ad/tracker blocklists are enabled so domains get blocked (and thus redirected here).",
		},
		YAML:    fmt.Sprintf("dns:\n  blocking_mode: custom_ip\n  blocking_ipv4: %s\n  blocking_ipv6: %s\n", blockingIPv4, blockingIPv6),
		Warning: "Copy these into AdGuard Home yourself — this tool never connects to or modifies AdGuard Home.",
	})
}
