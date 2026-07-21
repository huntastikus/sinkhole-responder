package admin

import (
	"net/http"
	"strconv"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/mgmt"
)

type statsResponse struct {
	Version          string            `json:"version"`
	StartedAt        string            `json:"started_at"`
	UptimeSeconds    int64             `json:"uptime_seconds"`
	RequestsTotal    uint64            `json:"requests_total"`
	RequestsByKind   map[string]uint64 `json:"requests_by_kind"`
	RequestsByStatus map[string]uint64 `json:"requests_by_status"`
	RPS              float64           `json:"rps"`
	RulesLoaded      int64             `json:"rules_loaded"`
	LeafCacheSize    int64             `json:"leaf_cache_size"`
	Duration         durationResponse  `json:"duration"`
}

type durationResponse struct {
	Buckets []durationBucketResponse `json:"buckets"`
	Sum     float64                  `json:"sum"`
	Count   uint64                   `json:"count"`
}

type durationBucketResponse struct {
	LE    string `json:"le"`
	Count uint64 `json:"count"`
}

type historyResponse struct {
	Range   string                  `json:"range"`
	Samples []historySampleResponse `json:"samples"`
}

type historySampleResponse struct {
	T             string             `json:"t"`
	RPS           float64            `json:"rps"`
	ByStatusClass map[string]float64 `json:"by_status_class"`
	LeafCache     int64              `json:"leaf_cache"`
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	snapshot := s.deps.Metrics.Snapshot()
	response := statsResponse{
		Version:          formatDisplayVersion(snapshot.Version),
		StartedAt:        snapshot.StartedAt.Format(time.RFC3339),
		RequestsTotal:    snapshot.RequestsTotal,
		RequestsByKind:   snapshot.RequestsByKind,
		RequestsByStatus: make(map[string]uint64, len(snapshot.RequestsByStatus)),
		RulesLoaded:      snapshot.RulesLoaded,
		LeafCacheSize:    snapshot.LeafCacheSize,
		Duration: durationResponse{
			Buckets: make([]durationBucketResponse, len(snapshot.DurationBuckets)),
			Sum:     snapshot.DurationSum,
			Count:   snapshot.DurationCount,
		},
	}
	if !snapshot.StartedAt.IsZero() {
		response.UptimeSeconds = int64(time.Since(snapshot.StartedAt) / time.Second)
	}
	for status, count := range snapshot.RequestsByStatus {
		response.RequestsByStatus[strconv.Itoa(status)] = count
	}
	for i, bucket := range snapshot.DurationBuckets {
		response.Duration.Buckets[i] = durationBucketResponse{LE: bucket.LE, Count: bucket.Count}
	}
	if s.deps.History != nil {
		samples := s.deps.History.Series("5m")
		if len(samples) > 0 {
			response.RPS = samples[len(samples)-1].RPS
		}
	}
	writeConfigJSON(w, http.StatusOK, response)
}

func (s *Server) handleStatsHistory(w http.ResponseWriter, r *http.Request) {
	rng := r.URL.Query().Get("range")
	if rng == "" {
		rng = "5m"
	}
	if rng != "5m" && rng != "3h" {
		writeConfigError(w, http.StatusBadRequest, "invalid range")
		return
	}

	response := historyResponse{
		Range:   rng,
		Samples: make([]historySampleResponse, 0),
	}
	if s.deps.History != nil {
		for _, sample := range s.deps.History.Series(rng) {
			response.Samples = append(response.Samples, historySampleJSON(sample))
		}
	}
	writeConfigJSON(w, http.StatusOK, response)
}

func historySampleJSON(sample mgmt.Sample) historySampleResponse {
	return historySampleResponse{
		T:             sample.T.Format(time.RFC3339),
		RPS:           sample.RPS,
		ByStatusClass: sample.ByStatusClass,
		LeafCache:     sample.LeafCache,
	}
}
