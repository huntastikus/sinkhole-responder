package mgmt

import (
	"testing"
	"time"
)

func TestStateRoundTrip(t *testing.T) {
	metrics := NewMetrics("v1")
	metrics.ObserveRequest("script", "r1", 200, 3*time.Millisecond)
	metrics.ObserveRequest("beacon", "", 204, time.Millisecond)
	history := NewHistory()
	history.Record(Snapshot{}, metrics.Snapshot(), time.Second, time.Now())

	data, err := MarshalState(metrics, history)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	restoredMetrics := NewMetrics("v2")
	restoredHistory := NewHistory()
	if err := RestoreState(restoredMetrics, restoredHistory, data); err != nil {
		t.Fatalf("restore: %v", err)
	}
	snapshot := restoredMetrics.Snapshot()
	if snapshot.RequestsTotal != 2 || snapshot.RequestsByRule["r1"] != 1 || snapshot.RequestsByKind["script"] != 1 {
		t.Fatalf("restored snapshot wrong: %+v", snapshot)
	}
	if snapshot.DurationCount != 2 {
		t.Fatalf("DurationCount = %d, want 2", snapshot.DurationCount)
	}
	if got := len(restoredHistory.Series("5m")); got != 1 {
		t.Fatalf("restored fine series length = %d, want 1", got)
	}
	if snapshot.Version != "v2" {
		t.Fatal("version must stay the new process's version")
	}
}

func TestRestoreStateRejectsGarbage(t *testing.T) {
	if err := RestoreState(NewMetrics(""), NewHistory(), []byte("{")); err == nil {
		t.Fatal("expected error")
	}
}
