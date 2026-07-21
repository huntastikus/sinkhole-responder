package mgmt

import (
	"testing"
	"time"
)

func TestHistoryRecordComputesRatesAndStatusClasses(t *testing.T) {
	t.Parallel()

	stamp := time.Date(2026, time.July, 20, 12, 0, 1, 0, time.UTC)
	prev := Snapshot{
		RequestsByStatus: map[int]uint64{200: 10, 302: 4, 404: 5, 503: 2},
	}
	cur := Snapshot{
		StartedAt:        stamp,
		RequestsTotal:    150,
		RequestsByStatus: map[int]uint64{199: 100, 200: 70, 204: 20, 302: 34, 404: 25, 503: 12, 600: 100},
		LeafCacheSize:    23,
	}

	history := NewHistory()
	history.Record(prev, cur, time.Second, stamp)

	series := history.Series("5m")
	if len(series) != 1 {
		t.Fatalf("Series(5m) length = %d, want 1", len(series))
	}
	sample := series[0]
	if !sample.T.Equal(stamp) {
		t.Errorf("sample timestamp = %v, want %v", sample.T, stamp)
	}
	if sample.RPS != 150 {
		t.Errorf("RPS = %v, want 150", sample.RPS)
	}
	wantRates := map[string]float64{
		"2xx": 80,
		"3xx": 30,
		"4xx": 20,
		"5xx": 10,
	}
	for class, want := range wantRates {
		if got := sample.ByStatusClass[class]; got != want {
			t.Errorf("ByStatusClass[%q] = %v, want %v", class, got, want)
		}
	}
	if sample.LeafCache != 23 {
		t.Errorf("LeafCache = %d, want 23", sample.LeafCache)
	}
}

func TestHistoryRecordClampsCounterResets(t *testing.T) {
	t.Parallel()

	history := NewHistory()
	history.Record(
		Snapshot{RequestsTotal: 100, RequestsByStatus: map[int]uint64{200: 80, 500: 20}},
		Snapshot{
			StartedAt:        time.Date(2026, time.July, 20, 12, 0, 1, 0, time.UTC),
			RequestsTotal:    5,
			RequestsByStatus: map[int]uint64{200: 4, 500: 1},
		},
		time.Second,
		time.Date(2026, time.July, 20, 12, 0, 1, 0, time.UTC),
	)

	sample := history.Series("5m")[0]
	if sample.RPS != 0 {
		t.Errorf("RPS after reset = %v, want 0", sample.RPS)
	}
	for class, rate := range sample.ByStatusClass {
		if rate < 0 {
			t.Errorf("ByStatusClass[%q] = %v, want non-negative", class, rate)
		}
	}
}

func TestHistorySeriesSelectsRingAndDefaultsToFine(t *testing.T) {
	t.Parallel()

	history := NewHistory()
	fineStamp := time.Date(2026, time.July, 20, 12, 0, 1, 0, time.UTC)
	coarseStamp := fineStamp.Add(time.Minute)
	history.Record(
		Snapshot{},
		Snapshot{StartedAt: fineStamp, RequestsTotal: 1},
		time.Second,
		fineStamp,
	)
	history.recordCoarse([]Sample{{T: coarseStamp, RPS: 2, LeafCache: 7}})

	for _, rng := range []string{"5m", "", "unknown"} {
		series := history.Series(rng)
		if len(series) != 1 || !series[0].T.Equal(fineStamp) {
			t.Errorf("Series(%q) = %#v, want the fine ring", rng, series)
		}
	}
	coarse := history.Series("3h")
	if len(coarse) != 1 || !coarse[0].T.Equal(coarseStamp) {
		t.Fatalf("Series(3h) = %#v, want the coarse ring", coarse)
	}
}

func TestHistoryRingsEvictOldestAndReturnOldestFirst(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	history := NewHistory()
	for i := 1; i <= fineCapacity+5; i++ {
		history.Record(
			Snapshot{RequestsTotal: uint64(i - 1)},
			Snapshot{StartedAt: base.Add(time.Duration(i) * time.Second), RequestsTotal: uint64(i)},
			time.Second,
			base.Add(time.Duration(i)*time.Second),
		)
	}

	fine := history.Series("5m")
	if len(fine) != fineCapacity {
		t.Fatalf("fine ring length = %d, want %d", len(fine), fineCapacity)
	}
	if want := base.Add(6 * time.Second); !fine[0].T.Equal(want) {
		t.Errorf("oldest fine timestamp = %v, want %v", fine[0].T, want)
	}
	if want := base.Add((fineCapacity + 5) * time.Second); !fine[len(fine)-1].T.Equal(want) {
		t.Errorf("newest fine timestamp = %v, want %v", fine[len(fine)-1].T, want)
	}

	for i := 1; i <= coarseCapacity+3; i++ {
		history.recordCoarse([]Sample{{
			T:             base.Add(time.Duration(i) * time.Minute),
			RPS:           float64(i),
			ByStatusClass: map[string]float64{"2xx": float64(i)},
			LeafCache:     int64(i),
		}})
	}
	coarse := history.Series("3h")
	if len(coarse) != coarseCapacity {
		t.Fatalf("coarse ring length = %d, want %d", len(coarse), coarseCapacity)
	}
	if want := base.Add(4 * time.Minute); !coarse[0].T.Equal(want) {
		t.Errorf("oldest coarse timestamp = %v, want %v", coarse[0].T, want)
	}
	if want := base.Add((coarseCapacity + 3) * time.Minute); !coarse[len(coarse)-1].T.Equal(want) {
		t.Errorf("newest coarse timestamp = %v, want %v", coarse[len(coarse)-1].T, want)
	}
}

func TestHistoryCoarseSampleAveragesRatesAndUsesLatestGauge(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	history := NewHistory()
	history.recordCoarse([]Sample{
		{T: base.Add(time.Second), RPS: 2, ByStatusClass: map[string]float64{"2xx": 1, "4xx": 1}, LeafCache: 3},
		{T: base.Add(2 * time.Second), RPS: 4, ByStatusClass: map[string]float64{"2xx": 3, "4xx": 1}, LeafCache: 9},
	})

	series := history.Series("3h")
	if len(series) != 1 {
		t.Fatalf("coarse series length = %d, want 1", len(series))
	}
	sample := series[0]
	if !sample.T.Equal(base.Add(2 * time.Second)) {
		t.Errorf("timestamp = %v, want latest sample timestamp", sample.T)
	}
	if sample.RPS != 3 {
		t.Errorf("RPS = %v, want average 3", sample.RPS)
	}
	if sample.ByStatusClass["2xx"] != 2 || sample.ByStatusClass["4xx"] != 1 {
		t.Errorf("ByStatusClass = %#v, want averaged rates", sample.ByStatusClass)
	}
	if sample.LeafCache != 9 {
		t.Errorf("LeafCache = %d, want latest gauge 9", sample.LeafCache)
	}
}
