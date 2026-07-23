package admin

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/config"
	"github.com/huntastikus/sinkhole-responder/internal/rulepacks"
	"github.com/huntastikus/sinkhole-responder/internal/state"
	"github.com/huntastikus/sinkhole-responder/internal/tlsx"
)

type healthStatus string

const (
	healthGreen healthStatus = "green"
	healthAmber healthStatus = "amber"
	healthRed   healthStatus = "red"
)

type healthCheck struct {
	Name   string       `json:"name"`
	Status healthStatus `json:"status"`
	Detail string       `json:"detail"`
}

type healthResponse struct {
	Overall        healthStatus  `json:"overall"`
	Checks         []healthCheck `json:"checks"`
	RestartPending bool          `json:"restart_pending"`
}

func (s *Server) handleSystemHealth(w http.ResponseWriter, _ *http.Request) {
	cfg := s.deps.Cfg()
	checks := []healthCheck{
		listenersHealth(cfg),
		tlsHealth(cfg, stateRootOf(s.deps.State)),
		stateDirHealth(s.deps.State),
		recentErrorsHealth(s),
		rulepacksHealth(cfg),
	}
	restartPending := s.deps.RestartPending != nil && s.deps.RestartPending()
	if restartPending {
		checks = append(checks, healthCheck{Name: "restart", Status: healthAmber, Detail: "restart required to apply saved changes"})
	}

	overall := healthGreen
	for _, check := range checks {
		if healthSeverity(check.Status) > healthSeverity(overall) {
			overall = check.Status
		}
	}
	writeConfigJSON(w, http.StatusOK, healthResponse{Overall: overall, Checks: checks, RestartPending: restartPending})
}

func listenersHealth(cfg *config.Config) healthCheck {
	httpCount := configuredCount(cfg.Listen.HTTP)
	httpsCount := configuredCount(cfg.Listen.HTTPS)
	adminCount := 0
	if strings.TrimSpace(cfg.Admin.Listen) != "" {
		adminCount++
	}
	if cfg.Admin.TLS.Enabled && strings.TrimSpace(cfg.Admin.TLS.Listen) != "" {
		adminCount++
	}
	detail := fmt.Sprintf("%d HTTP, %d HTTPS, %d admin configured", httpCount, httpsCount, adminCount)
	if httpCount+httpsCount == 0 {
		return healthCheck{Name: "listeners", Status: healthRed, Detail: detail}
	}
	return healthCheck{Name: "listeners", Status: healthGreen, Detail: detail}
}

func configuredCount(addresses []string) int {
	count := 0
	for _, address := range addresses {
		if strings.TrimSpace(address) != "" {
			count++
		}
	}
	return count
}

const certExpiryWarn = 30 * 24 * time.Hour

func stateRootOf(dir *state.Dir) string {
	if dir == nil {
		return ""
	}
	return dir.Root
}

// expiryStatus grades a certificate's NotAfter: red when expired, amber when
// inside the warn window, green otherwise.
func expiryStatus(label string, notAfter, now time.Time) (healthStatus, string) {
	date := notAfter.UTC().Format("2006-01-02")
	switch {
	case now.After(notAfter):
		return healthRed, fmt.Sprintf("%s expired %s", label, date)
	case now.Add(certExpiryWarn).After(notAfter):
		return healthAmber, fmt.Sprintf("%s expires %s", label, date)
	default:
		return healthGreen, fmt.Sprintf("%s expires %s", label, date)
	}
}

func tlsHealth(cfg *config.Config, stateRoot string) healthCheck {
	switch cfg.TLS.Mode {
	case "disabled":
		return healthCheck{Name: "tls", Status: healthAmber, Detail: "HTTPS off"}
	case "static":
		return staticTLSHealth(cfg)
	case "local-ca":
		return localCATLSHealth(cfg, stateRoot)
	default:
		return healthCheck{Name: "tls", Status: healthRed, Detail: "TLS mode misconfigured"}
	}
}

func staticTLSHealth(cfg *config.Config) healthCheck {
	if len(cfg.TLS.Static.Certs) == 0 {
		return healthCheck{Name: "tls", Status: healthRed, Detail: "static certificate paths missing"}
	}
	now := time.Now()
	var soonest time.Time
	for i, pair := range cfg.TLS.Static.Certs {
		if strings.TrimSpace(pair.CertFile) == "" || strings.TrimSpace(pair.KeyFile) == "" {
			return healthCheck{Name: "tls", Status: healthRed, Detail: "static certificate paths missing"}
		}
		certificate, err := tls.LoadX509KeyPair(pair.CertFile, pair.KeyFile)
		if err != nil {
			return healthCheck{Name: "tls", Status: healthRed, Detail: fmt.Sprintf("static certificate pair %d unreadable", i+1)}
		}
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return healthCheck{Name: "tls", Status: healthRed, Detail: fmt.Sprintf("static certificate pair %d unparseable", i+1)}
		}
		if soonest.IsZero() || leaf.NotAfter.Before(soonest) {
			soonest = leaf.NotAfter
		}
	}
	status, detail := expiryStatus(fmt.Sprintf("%d static certificate pair(s), soonest", len(cfg.TLS.Static.Certs)), soonest, now)
	return healthCheck{Name: "tls", Status: status, Detail: detail}
}

func localCATLSHealth(cfg *config.Config, stateRoot string) healthCheck {
	caCert := strings.TrimSpace(cfg.TLS.LocalCA.CACert)
	caKey := strings.TrimSpace(cfg.TLS.LocalCA.CAKey)
	if (caCert == "") != (caKey == "") {
		return healthCheck{Name: "tls", Status: healthRed, Detail: "local CA paths must be set together"}
	}
	if caCert == "" && stateRoot == "" {
		// No configured paths and no state dir to resolve the generated
		// location against; keep the pre-inspection behavior.
		return healthCheck{Name: "tls", Status: healthGreen, Detail: "local CA (auto-generated)"}
	}
	certPath, keyPath := tlsx.ResolveCAPaths(cfg.TLS.LocalCA, stateRoot)
	if _, err := os.Stat(certPath); err != nil {
		if os.IsNotExist(err) {
			if caCert != "" {
				return healthCheck{Name: "tls", Status: healthAmber, Detail: "configured local CA files not found"}
			}
			return healthCheck{Name: "tls", Status: healthAmber, Detail: "local CA not generated yet"}
		}
		return healthCheck{Name: "tls", Status: healthRed, Detail: "local CA certificate unreadable"}
	}
	if _, err := os.Stat(keyPath); err != nil {
		return healthCheck{Name: "tls", Status: healthRed, Detail: "local CA key missing"}
	}
	// Load the full pair, mirroring loadLocalCA's real serving-path check, so a
	// corrupt or mismatched CA key cannot report green.
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return healthCheck{Name: "tls", Status: healthRed, Detail: "local CA certificate or key invalid"}
	}
	ca, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return healthCheck{Name: "tls", Status: healthRed, Detail: "local CA certificate unparseable"}
	}
	status, detail := expiryStatus("local CA", ca.NotAfter, time.Now())
	return healthCheck{Name: "tls", Status: status, Detail: detail}
}

func stateDirHealth(dir *state.Dir) healthCheck {
	if dir == nil || strings.TrimSpace(dir.Root) == "" {
		return healthCheck{Name: "state_dir", Status: healthRed, Detail: "config save disabled"}
	}
	info, err := os.Stat(dir.Root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o222 == 0 {
		return healthCheck{Name: "state_dir", Status: healthRed, Detail: "config save disabled"}
	}
	probe, err := os.CreateTemp(dir.Root, ".health-*")
	if err != nil {
		return healthCheck{Name: "state_dir", Status: healthRed, Detail: "config save disabled"}
	}
	probePath := probe.Name()
	if err := probe.Close(); err != nil {
		_ = os.Remove(probePath)
		return healthCheck{Name: "state_dir", Status: healthRed, Detail: "config save disabled"}
	}
	if err := os.Remove(probePath); err != nil {
		return healthCheck{Name: "state_dir", Status: healthRed, Detail: "config save disabled"}
	}
	return healthCheck{Name: "state_dir", Status: healthGreen, Detail: "writable"}
}

func recentErrorsHealth(s *Server) healthCheck {
	count := 0
	if s.deps.LogBuf != nil {
		count = len(s.deps.LogBuf.Snapshot(slog.LevelError, 50))
	}
	status := healthGreen
	if count >= 5 {
		status = healthRed
	} else if count > 0 {
		status = healthAmber
	}
	return healthCheck{Name: "recent_errors", Status: status, Detail: fmt.Sprintf("%d recent errors", count)}
}

func rulepacksHealth(cfg *config.Config) healthCheck {
	enabled := len(cfg.Rulepacks.Enabled)
	if enabled == 0 {
		return healthCheck{Name: "rulepacks", Status: healthAmber, Detail: "no adblock packs enabled"}
	}
	return healthCheck{
		Name:   "rulepacks",
		Status: healthGreen,
		Detail: fmt.Sprintf("%d of %d available enabled", enabled, len(rulepacks.Available())),
	}
}

func healthSeverity(status healthStatus) int {
	switch status {
	case healthRed:
		return 2
	case healthAmber:
		return 1
	default:
		return 0
	}
}
