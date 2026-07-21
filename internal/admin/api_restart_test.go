package admin

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestHandleRestart(t *testing.T) {
	server, _ := newHealthTestServer(t, greenHealthConfig())

	var mu sync.Mutex
	triggered := 0
	done := make(chan struct{}, 1)
	server.restartDelay = 0
	server.triggerRestart = func() {
		mu.Lock()
		triggered++
		mu.Unlock()
		select {
		case done <- struct{}{}:
		default:
		}
	}

	first := httptest.NewRecorder()
	server.handleRestart(first, httptest.NewRequest(http.MethodPost, "/api/system/restart", nil))
	if first.Code != http.StatusAccepted {
		t.Fatalf("first restart status = %d, want %d; body=%s", first.Code, http.StatusAccepted, first.Body.String())
	}

	// A second request while one is already in progress is rejected.
	second := httptest.NewRecorder()
	server.handleRestart(second, httptest.NewRequest(http.MethodPost, "/api/system/restart", nil))
	if second.Code != http.StatusConflict {
		t.Fatalf("second restart status = %d, want %d", second.Code, http.StatusConflict)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("triggerRestart was never invoked")
	}
	mu.Lock()
	defer mu.Unlock()
	if triggered != 1 {
		t.Fatalf("triggerRestart called %d times, want 1", triggered)
	}
}
