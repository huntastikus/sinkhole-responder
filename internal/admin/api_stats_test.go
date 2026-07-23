package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/config"
	"github.com/huntastikus/sinkhole-responder/internal/mgmt"
)

type statsAPIResponse struct {
	Version          string            `json:"version"`
	StartedAt        string            `json:"started_at"`
	UptimeSeconds    int64             `json:"uptime_seconds"`
	RequestsTotal    uint64            `json:"requests_total"`
	RequestsByKind   map[string]uint64 `json:"requests_by_kind"`
	RequestsByStatus map[string]uint64 `json:"requests_by_status"`
	RequestsByRule   map[string]uint64 `json:"requests_by_rule"`
	RPS              float64           `json:"rps"`
	RulesLoaded      int64             `json:"rules_loaded"`
	LeafCacheSize    int64             `json:"leaf_cache_size"`
	Duration         struct {
		Buckets []mgmt.BucketCount `json:"buckets"`
		Sum     float64            `json:"sum"`
		Count   uint64             `json:"count"`
	} `json:"duration"`
}

type historyAPIResponse struct {
	Range   string `json:"range"`
	Samples []struct {
		T             string             `json:"t"`
		RPS           float64            `json:"rps"`
		ByStatusClass map[string]float64 `json:"by_status_class"`
		LeafCache     int64              `json:"leaf_cache"`
	} `json:"samples"`
}

func TestStatsAPIReportsCurrentSnapshot(t *testing.T) {
	metrics := mgmt.NewMetrics("v2.3.4")
	metrics.ObserveRequest("js", "block-js", http.StatusOK, 2*time.Millisecond)
	metrics.ObserveRequest("js", "block-js", http.StatusOK, 30*time.Millisecond)
	metrics.ObserveRequest("image", "", http.StatusNoContent, time.Millisecond)
	metrics.SetRuleCount(7)
	metrics.SetLeafCacheSize(11)
	history := mgmt.NewHistory()
	history.Record(
		mgmt.Snapshot{RequestsTotal: 5, RequestsByStatus: map[int]uint64{200: 5}},
		mgmt.Snapshot{StartedAt: time.Unix(100, 0), RequestsTotal: 7, RequestsByStatus: map[int]uint64{200: 7}},
		2*time.Second,
		time.Date(2026, time.July, 20, 10, 0, 0, 0, time.UTC),
	)
	history.Record(
		mgmt.Snapshot{RequestsTotal: 7, RequestsByStatus: map[int]uint64{200: 7}},
		mgmt.Snapshot{StartedAt: time.Unix(110, 0), RequestsTotal: 13, RequestsByStatus: map[int]uint64{200: 11, 404: 2}},
		2*time.Second,
		time.Date(2026, time.July, 20, 10, 0, 2, 0, time.UTC),
	)
	server := newStatsTestServer(t, metrics, history)
	saveTestCredential(t, server, "correct horse battery staple")
	snapshot := metrics.Snapshot()

	response := performJSONRequest(t, server, http.MethodGet, "/api/stats", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	var body statsAPIResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Version != snapshot.Version {
		t.Errorf("version = %q, want %q", body.Version, snapshot.Version)
	}
	if body.StartedAt != snapshot.StartedAt.Format(time.RFC3339) {
		t.Errorf("started_at = %q, want %q", body.StartedAt, snapshot.StartedAt.Format(time.RFC3339))
	}
	wantUptime := int64(time.Since(snapshot.StartedAt) / time.Second)
	if body.UptimeSeconds != wantUptime {
		t.Errorf("uptime_seconds = %d, want %d", body.UptimeSeconds, wantUptime)
	}
	if body.RequestsTotal != 3 {
		t.Errorf("requests_total = %d, want 3", body.RequestsTotal)
	}
	if want := map[string]uint64{"image": 1, "js": 2}; !reflect.DeepEqual(body.RequestsByKind, want) {
		t.Errorf("requests_by_kind = %#v, want %#v", body.RequestsByKind, want)
	}
	if want := map[string]uint64{"200": 2, "204": 1}; !reflect.DeepEqual(body.RequestsByStatus, want) {
		t.Errorf("requests_by_status = %#v, want %#v", body.RequestsByStatus, want)
	}
	if want := map[string]uint64{"block-js": 2}; !reflect.DeepEqual(body.RequestsByRule, want) {
		t.Errorf("requests_by_rule = %#v, want %#v", body.RequestsByRule, want)
	}
	if body.RPS != 3 {
		t.Errorf("rps = %v, want 3", body.RPS)
	}
	if body.RulesLoaded != 7 || body.LeafCacheSize != 11 {
		t.Errorf("rules_loaded/leaf_cache_size = %d/%d, want 7/11", body.RulesLoaded, body.LeafCacheSize)
	}
	if !reflect.DeepEqual(body.Duration.Buckets, snapshot.DurationBuckets) {
		t.Errorf("duration buckets = %#v, want %#v", body.Duration.Buckets, snapshot.DurationBuckets)
	}
	if body.Duration.Sum != snapshot.DurationSum || body.Duration.Count != snapshot.DurationCount {
		t.Errorf("duration sum/count = %v/%d, want %v/%d", body.Duration.Sum, body.Duration.Count, snapshot.DurationSum, snapshot.DurationCount)
	}
}

func TestStatsHistoryAPISelectsRange(t *testing.T) {
	history := mgmt.NewHistory()
	stamp := time.Date(2026, time.July, 20, 12, 34, 56, 0, time.UTC)
	history.Record(
		mgmt.Snapshot{RequestsByStatus: map[int]uint64{}},
		mgmt.Snapshot{
			StartedAt:        stamp,
			RequestsTotal:    20,
			RequestsByStatus: map[int]uint64{200: 10, 302: 2, 404: 5, 503: 3},
			LeafCacheSize:    9,
		},
		10*time.Second,
		stamp,
	)
	server := newStatsTestServer(t, mgmt.NewMetrics("test"), history)
	saveTestCredential(t, server, "correct horse battery staple")

	t.Run("coarse 3h series", func(t *testing.T) {
		response := performJSONRequest(t, server, http.MethodGet, "/api/stats/history?range=3h", nil)
		body := decodeHistoryResponse(t, response, http.StatusOK)
		if body.Range != "3h" {
			t.Errorf("range = %q, want 3h", body.Range)
		}
		if body.Samples == nil || len(body.Samples) != 0 {
			t.Errorf("samples = %#v, want non-nil empty coarse series", body.Samples)
		}
	})

	t.Run("default fine 5m series", func(t *testing.T) {
		response := performJSONRequest(t, server, http.MethodGet, "/api/stats/history", nil)
		body := decodeHistoryResponse(t, response, http.StatusOK)
		if body.Range != "5m" {
			t.Errorf("range = %q, want 5m", body.Range)
		}
		if len(body.Samples) != 1 {
			t.Fatalf("sample count = %d, want 1", len(body.Samples))
		}
		sample := body.Samples[0]
		if sample.T != stamp.Format(time.RFC3339) || sample.RPS != 2 || sample.LeafCache != 9 {
			t.Errorf("sample = %#v, want stamp %q, rps 2, leaf cache 9", sample, stamp.Format(time.RFC3339))
		}
		wantClasses := map[string]float64{"2xx": 1, "3xx": 0.2, "4xx": 0.5, "5xx": 0.3}
		if !reflect.DeepEqual(sample.ByStatusClass, wantClasses) {
			t.Errorf("by_status_class = %#v, want %#v", sample.ByStatusClass, wantClasses)
		}
	})

	t.Run("invalid range", func(t *testing.T) {
		response := performJSONRequest(t, server, http.MethodGet, "/api/stats/history?range=foo", nil)
		if response.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", response.Code, http.StatusBadRequest)
		}
	})
}

func TestStatsHistoryAPINilHistoryReturnsEmptySamples(t *testing.T) {
	server := newStatsTestServer(t, mgmt.NewMetrics("test"), nil)
	saveTestCredential(t, server, "correct horse battery staple")

	response := performJSONRequest(t, server, http.MethodGet, "/api/stats/history", nil)
	body := decodeHistoryResponse(t, response, http.StatusOK)

	if body.Range != "5m" || body.Samples == nil || len(body.Samples) != 0 {
		t.Errorf("response = %#v, want range 5m and non-nil empty samples", body)
	}
}

func TestStatsAPIRequiresAuthentication(t *testing.T) {
	server := newStatsTestServer(t, mgmt.NewMetrics("test"), nil)
	saveTestCredential(t, server, "correct horse battery staple")
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/stats", nil))

	assertRedirect(t, response.Result(), "/login")
}

func TestStatsAPIsRejectNonGETMethods(t *testing.T) {
	server := newStatsTestServer(t, mgmt.NewMetrics("test"), nil)
	saveTestCredential(t, server, "correct horse battery staple")
	for _, path := range []string{"/api/stats", "/api/stats/history"} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, path, nil)
			request.AddCookie(validSessionCookie(t, server))
			request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "test-csrf"})
			request.Header.Set("X-CSRF-Token", "test-csrf")
			response := httptest.NewRecorder()

			server.Handler().ServeHTTP(response, request)

			if response.Code != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func newStatsTestServer(t *testing.T, metrics *mgmt.Metrics, history *mgmt.History) *Server {
	t.Helper()
	base := newTestServer(t, config.AdminConfig{})
	server, err := New(Deps{
		Cfg:     base.deps.Cfg,
		Metrics: metrics,
		History: history,
		State:   base.deps.State,
		Logger:  base.logger,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if server.deps.History != history {
		t.Fatal("New did not store the history dependency")
	}
	return server
}

func decodeHistoryResponse(t *testing.T, response *httptest.ResponseRecorder, wantStatus int) historyAPIResponse {
	t.Helper()
	if response.Code != wantStatus {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, wantStatus, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var body historyAPIResponse
	decodeJSON(t, response, &body)
	return body
}
