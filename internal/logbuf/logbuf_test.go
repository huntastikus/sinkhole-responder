package logbuf

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestRingKeepsLastN(t *testing.T) {
	ring := NewRing(3)
	handler := ring.Handler(newCaptureHandler())

	for i := range 5 {
		handleRecord(t, handler, slog.LevelInfo, fmt.Sprintf("message-%d", i))
	}

	records := ring.Snapshot(slog.LevelDebug, 10)
	if len(records) != 3 {
		t.Fatalf("Snapshot() returned %d records, want 3", len(records))
	}
	want := []string{"message-4", "message-3", "message-2"}
	for i, record := range records {
		if record.Msg != want[i] {
			t.Errorf("Snapshot()[%d].Msg = %q, want %q", i, record.Msg, want[i])
		}
	}
}

func TestSnapshotFiltersByLevelNewestFirstAndLimits(t *testing.T) {
	ring := NewRing(10)
	handler := ring.Handler(newCaptureHandler())

	handleRecord(t, handler, slog.LevelInfo, "old-info")
	handleRecord(t, handler, slog.LevelError, "new-error")
	handleRecord(t, handler, slog.LevelWarn, "newest-warn")

	records := ring.Snapshot(slog.LevelWarn, 2)
	if len(records) != 2 {
		t.Fatalf("Snapshot() returned %d records, want 2", len(records))
	}
	if records[0].Msg != "newest-warn" || records[0].Level != "WARN" {
		t.Errorf("Snapshot()[0] = %#v, want newest WARN record", records[0])
	}
	if records[1].Msg != "new-error" || records[1].Level != "ERROR" {
		t.Errorf("Snapshot()[1] = %#v, want older ERROR record", records[1])
	}
}

func TestHandlerForwardsToNext(t *testing.T) {
	ring := NewRing(10)
	next := newCaptureHandler()
	handler := ring.Handler(next)

	handleRecord(t, handler, slog.LevelInfo, "forwarded", slog.String("key", "value"))

	records := next.snapshot()
	if len(records) != 1 {
		t.Fatalf("next handler received %d records, want 1", len(records))
	}
	if records[0].Message != "forwarded" {
		t.Errorf("forwarded message = %q, want %q", records[0].Message, "forwarded")
	}
}

func TestHandlerCapturesWithAttrsAndGroups(t *testing.T) {
	ring := NewRing(10)
	logger := slog.New(ring.Handler(newCaptureHandler())).
		With("component", "test").
		WithGroup("request").
		With("method", "GET")

	logger.Info("served", "status", 200)

	records := ring.Snapshot(slog.LevelInfo, 1)
	if len(records) != 1 {
		t.Fatalf("Snapshot() returned %d records, want 1", len(records))
	}
	if got := records[0].Attrs["component"]; got != "test" {
		t.Errorf("component attr = %#v, want %q", got, "test")
	}
	request, ok := records[0].Attrs["request"].(map[string]any)
	if !ok {
		t.Fatalf("request attr = %#v, want a grouped attr map", records[0].Attrs["request"])
	}
	if got := request["method"]; got != "GET" {
		t.Errorf("request.method = %#v, want %q", got, "GET")
	}
	if got := request["status"]; got != int64(200) {
		t.Errorf("request.status = %#v, want int64(200)", got)
	}
}

func TestHandlerIgnoresEmptyGroups(t *testing.T) {
	ring := NewRing(10)
	logger := slog.New(ring.Handler(newCaptureHandler())).
		WithGroup("outer").
		With(slog.Group("context-empty"))

	logger.Info("empty groups", slog.Group("record-empty"))

	records := ring.Snapshot(slog.LevelInfo, 1)
	if len(records) != 1 {
		t.Fatalf("Snapshot() returned %d records, want 1", len(records))
	}
	if len(records[0].Attrs) != 0 {
		t.Errorf("Attrs = %#v, want empty groups to be omitted", records[0].Attrs)
	}
}

func TestHandlerWithEmptyGroupReturnsReceiver(t *testing.T) {
	handler := NewRing(10).Handler(newCaptureHandler())
	if got := handler.WithGroup(""); got != handler {
		t.Errorf("WithGroup(\"\") returned %T %p, want receiver %T %p", got, got, handler, handler)
	}
}

func TestConcurrentWrites(t *testing.T) {
	ring := NewRing(64)
	handler := ring.Handler(newCaptureHandler())

	const (
		writers   = 16
		perWriter = 100
	)
	var wg sync.WaitGroup
	for writer := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for entry := range perWriter {
				record := slog.NewRecord(time.Now(), slog.LevelInfo, "concurrent", 0)
				record.AddAttrs(slog.Int("writer", writer), slog.Int("entry", entry))
				if err := handler.Handle(context.Background(), record); err != nil {
					t.Errorf("Handle() error = %v", err)
				}
			}
		}()
	}
	wg.Wait()

	if got := len(ring.Snapshot(slog.LevelInfo, 100)); got != 64 {
		t.Errorf("Snapshot() returned %d records, want 64", got)
	}
}

func handleRecord(t *testing.T, handler slog.Handler, level slog.Level, message string, attrs ...slog.Attr) {
	t.Helper()
	record := slog.NewRecord(time.Now(), level, message, 0)
	record.AddAttrs(attrs...)
	if err := handler.Handle(context.Background(), record); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
}

type captureHandler struct {
	state *captureState
}

type captureState struct {
	mu      sync.Mutex
	records []slog.Record
}

func newCaptureHandler() *captureHandler {
	return &captureHandler{state: &captureState{}}
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *captureHandler) Handle(_ context.Context, record slog.Record) error {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()
	h.state.records = append(h.state.records, record.Clone())
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler {
	return &captureHandler{state: h.state}
}

func (h *captureHandler) WithGroup(string) slog.Handler {
	return &captureHandler{state: h.state}
}

func (h *captureHandler) snapshot() []slog.Record {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()
	return append([]slog.Record(nil), h.state.records...)
}
