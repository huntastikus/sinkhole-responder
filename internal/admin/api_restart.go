package admin

import (
	"fmt"
	"net/http"
	"os"
	"syscall"
	"time"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/config"
)

// restartSignalDelay gives the 202 response time to reach the browser before the
// process begins its graceful shutdown.
const restartSignalDelay = 300 * time.Millisecond

// handleRestart triggers a graceful process restart so that startup-only
// configuration changes (listeners, TLS, request limits, the admin plane, and
// the state directory) take effect. The process exits cleanly through the
// existing SIGTERM path; a supervisor — a Docker restart policy or systemd —
// relaunches it. A bare binary with no supervisor will stop and stay down, which
// the GUI confirmation dialog warns about.
func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if !s.restartInProgress.CompareAndSwap(false, true) {
		writeConfigError(w, http.StatusConflict, "a restart is already in progress")
		return
	}
	// Preflight: never take a running responder down for a configuration that
	// cannot boot. Config saved through the GUI is validated on write, but it may
	// have been edited on disk since. This checks parse+validate only, not runtime
	// bindability; the supervisor's restart backoff bounds a bad-bind loop.
	if s.deps.ConfigPath != "" {
		if _, err := config.Load(s.deps.ConfigPath); err != nil {
			s.restartInProgress.Store(false)
			writeConfigError(w, http.StatusBadRequest, fmt.Sprintf("on-disk configuration will not load; not restarting: %v", err))
			return
		}
	}
	s.logger.Warn("admin-initiated restart requested", "remote_addr", r.RemoteAddr)
	writeConfigJSON(w, http.StatusAccepted, map[string]string{"status": "restarting"})
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	go func() {
		time.Sleep(s.restartDelay)
		s.triggerRestart()
	}()
}

// signalSelfTerminate sends SIGTERM to this process, invoking the graceful
// shutdown already wired to SIGINT/SIGTERM in main. It is the production value
// of Server.triggerRestart; tests override that field.
func (s *Server) signalSelfTerminate() {
	process, err := os.FindProcess(os.Getpid())
	if err != nil {
		s.logger.Error("restart: find own process", "error", err)
		s.restartInProgress.Store(false)
		return
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		s.logger.Error("restart: signal self", "error", err)
		s.restartInProgress.Store(false)
	}
}
