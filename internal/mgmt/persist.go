package mgmt

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

type persistedRequest struct {
	Kind   string `json:"kind"`
	Status int    `json:"status"`
	Count  uint64 `json:"count"`
}

type persistedState struct {
	SavedAt         time.Time          `json:"saved_at"`
	Requests        []persistedRequest `json:"requests"`
	Rules           map[string]uint64  `json:"rules"`
	DurationBuckets []uint64           `json:"duration_buckets"`
	DurationCount   uint64             `json:"duration_count"`
	DurationNanos   int64              `json:"duration_nanos"`
	Fine            []Sample           `json:"fine"`
	Coarse          []Sample           `json:"coarse"`
}

// MarshalState serializes the counters and history rings for restart persistence.
func MarshalState(m *Metrics, h *History) ([]byte, error) {
	if m == nil || h == nil {
		return nil, errors.New("metrics and history are required")
	}

	state := persistedState{
		SavedAt:         time.Now().UTC(),
		Rules:           make(map[string]uint64),
		DurationBuckets: make([]uint64, len(m.durationBuckets)),
	}
	m.requestsMu.RLock()
	state.Requests = make([]persistedRequest, 0, len(m.requests))
	for key, count := range m.requests {
		state.Requests = append(state.Requests, persistedRequest{
			Kind:   key.kind,
			Status: key.status,
			Count:  count,
		})
	}
	for rule, count := range m.rules {
		state.Rules[rule] = count
	}
	copy(state.DurationBuckets, m.durationBuckets[:])
	state.DurationCount = m.durationCount
	state.DurationNanos = m.durationNanos
	m.requestsMu.RUnlock()

	sort.Slice(state.Requests, func(i, j int) bool {
		if state.Requests[i].Kind == state.Requests[j].Kind {
			return state.Requests[i].Status < state.Requests[j].Status
		}
		return state.Requests[i].Kind < state.Requests[j].Kind
	})
	state.Fine, state.Coarse = h.dump()
	return json.Marshal(state)
}

// RestoreState merges a previously saved state into fresh metrics/history.
// Call before any traffic or sampling starts.
func RestoreState(m *Metrics, h *History, data []byte) error {
	if m == nil || h == nil {
		return errors.New("metrics and history are required")
	}
	if len(data) == 0 {
		return errors.New("metrics state is empty")
	}

	var saved persistedState
	if err := json.Unmarshal(data, &saved); err != nil {
		return fmt.Errorf("decode metrics state: %w", err)
	}
	if len(saved.DurationBuckets) != len(durationLabels) {
		return fmt.Errorf("duration bucket count = %d, want %d", len(saved.DurationBuckets), len(durationLabels))
	}

	m.requestsMu.Lock()
	m.requests = make(map[requestKey]uint64, len(saved.Requests))
	for _, request := range saved.Requests {
		m.requests[requestKey{kind: request.Kind, status: request.Status}] = request.Count
	}
	m.rules = make(map[string]uint64, len(saved.Rules))
	for rule, count := range saved.Rules {
		m.rules[rule] = count
	}
	copy(m.durationBuckets[:], saved.DurationBuckets)
	m.durationCount = saved.DurationCount
	m.durationNanos = saved.DurationNanos
	m.requestsMu.Unlock()

	h.restore(saved.Fine, saved.Coarse)
	return nil
}
