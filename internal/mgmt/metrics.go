package mgmt

import (
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var durationBounds = [...]time.Duration{
	time.Millisecond,
	5 * time.Millisecond,
	25 * time.Millisecond,
	100 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
	5 * time.Second,
}

var durationLabels = [...]string{"0.001", "0.005", "0.025", "0.1", "0.5", "1", "5", "+Inf"}

type requestKey struct {
	kind   string
	status int
}

// BucketCount is a cumulative duration histogram bucket.
type BucketCount struct {
	LE    string
	Count uint64
}

// Snapshot is a point-in-time copy of the process metrics.
type Snapshot struct {
	Version          string
	StartedAt        time.Time
	RequestsByKind   map[string]uint64
	RequestsByStatus map[int]uint64
	RequestsTotal    uint64
	DurationBuckets  []BucketCount
	DurationSum      float64
	DurationCount    uint64
	RulesLoaded      int64
	LeafCacheSize    int64

	requests map[requestKey]uint64
}

// Metrics stores the process metrics exposed by the management listener.
type Metrics struct {
	version   string
	startedAt time.Time

	requestsMu sync.RWMutex
	requests   map[requestKey]uint64

	durationBuckets [len(durationLabels)]uint64
	durationCount   uint64
	durationNanos   int64
	ruleCount       atomic.Int64
	leafCacheSize   atomic.Int64
}

// NewMetrics returns an empty metric registry for the supplied build version.
func NewMetrics(version string) *Metrics {
	return newMetrics(version, time.Now)
}

func newMetrics(version string, now func() time.Time) *Metrics {
	metrics := &Metrics{
		version:   version,
		startedAt: now(),
		requests:  make(map[requestKey]uint64),
	}
	return metrics
}

// ObserveRequest records one completed sinkhole request.
func (m *Metrics) ObserveRequest(kind string, status int, d time.Duration) {
	if m == nil {
		return
	}

	bucket := len(durationBounds)
	for i, bound := range durationBounds {
		if d <= bound {
			bucket = i
			break
		}
	}

	key := requestKey{kind: kind, status: status}
	m.requestsMu.Lock()
	m.requests[key]++
	m.durationBuckets[bucket]++
	m.durationCount++
	m.durationNanos += d.Nanoseconds()
	m.requestsMu.Unlock()
}

// SetLeafCacheSize updates the number of entries in the TLS leaf cache.
func (m *Metrics) SetLeafCacheSize(n int) {
	if m != nil {
		m.leafCacheSize.Store(int64(n))
	}
}

// SetRuleCount updates the number of loaded response rules.
func (m *Metrics) SetRuleCount(n int) {
	if m != nil {
		m.ruleCount.Store(int64(n))
	}
}

// Snapshot returns a point-in-time copy of the process metrics.
func (m *Metrics) Snapshot() Snapshot {
	snapshot := Snapshot{
		RequestsByKind:   make(map[string]uint64),
		RequestsByStatus: make(map[int]uint64),
		DurationBuckets:  make([]BucketCount, len(durationLabels)),
		requests:         make(map[requestKey]uint64),
	}
	if m == nil {
		for i, label := range durationLabels {
			snapshot.DurationBuckets[i].LE = label
		}
		return snapshot
	}

	snapshot.Version = m.version
	snapshot.StartedAt = m.startedAt

	m.requestsMu.RLock()
	for key, value := range m.requests {
		snapshot.requests[key] = value
		snapshot.RequestsByKind[key.kind] += value
		snapshot.RequestsByStatus[key.status] += value
		snapshot.RequestsTotal += value
	}
	var cumulative uint64
	for i, label := range durationLabels {
		cumulative += m.durationBuckets[i]
		snapshot.DurationBuckets[i] = BucketCount{LE: label, Count: cumulative}
	}
	snapshot.DurationSum = float64(m.durationNanos) / float64(time.Second)
	snapshot.DurationCount = m.durationCount
	snapshot.RulesLoaded = m.ruleCount.Load()
	snapshot.LeafCacheSize = m.leafCacheSize.Load()
	m.requestsMu.RUnlock()

	return snapshot
}

// WritePrometheus writes a complete Prometheus text exposition snapshot.
func (m *Metrics) WritePrometheus(w io.Writer) {
	var output strings.Builder
	output.WriteString("# HELP sinkhole_requests_total Total sinkhole requests by response kind and HTTP status.\n")
	output.WriteString("# TYPE sinkhole_requests_total counter\n")

	snapshot := m.Snapshot()
	keys := make([]requestKey, 0, len(snapshot.requests))
	for key := range snapshot.requests {
		keys = append(keys, key)
	}

	sort.Slice(keys, func(i, j int) bool {
		if keys[i].kind == keys[j].kind {
			return keys[i].status < keys[j].status
		}
		return keys[i].kind < keys[j].kind
	})
	for _, key := range keys {
		output.WriteString("sinkhole_requests_total{kind=\"")
		output.WriteString(key.kind)
		output.WriteString("\",status=\"")
		output.WriteString(strconv.Itoa(key.status))
		output.WriteString("\"} ")
		output.WriteString(strconv.FormatUint(snapshot.requests[key], 10))
		output.WriteByte('\n')
	}

	output.WriteString("# HELP sinkhole_request_duration_seconds Sinkhole request duration in seconds.\n")
	output.WriteString("# TYPE sinkhole_request_duration_seconds histogram\n")
	for _, bucket := range snapshot.DurationBuckets {
		output.WriteString("sinkhole_request_duration_seconds_bucket{le=\"")
		output.WriteString(bucket.LE)
		output.WriteString("\"} ")
		output.WriteString(strconv.FormatUint(bucket.Count, 10))
		output.WriteByte('\n')
	}
	output.WriteString("sinkhole_request_duration_seconds_sum ")
	output.WriteString(strconv.FormatFloat(snapshot.DurationSum, 'g', -1, 64))
	output.WriteByte('\n')
	output.WriteString("sinkhole_request_duration_seconds_count ")
	output.WriteString(strconv.FormatUint(snapshot.DurationCount, 10))
	output.WriteByte('\n')

	output.WriteString("# HELP sinkhole_rules_loaded Number of response rules currently loaded.\n")
	output.WriteString("# TYPE sinkhole_rules_loaded gauge\n")
	output.WriteString("sinkhole_rules_loaded ")
	output.WriteString(strconv.FormatInt(snapshot.RulesLoaded, 10))
	output.WriteByte('\n')

	output.WriteString("# HELP sinkhole_tls_leaf_cache_entries Number of entries in the TLS leaf certificate cache.\n")
	output.WriteString("# TYPE sinkhole_tls_leaf_cache_entries gauge\n")
	output.WriteString("sinkhole_tls_leaf_cache_entries ")
	output.WriteString(strconv.FormatInt(snapshot.LeafCacheSize, 10))
	output.WriteByte('\n')

	output.WriteString("# HELP sinkhole_build_info Sinkhole responder build information.\n")
	output.WriteString("# TYPE sinkhole_build_info gauge\n")
	output.WriteString("sinkhole_build_info{version=\"")
	output.WriteString(escapeLabelValue(snapshot.Version))
	output.WriteString("\"} 1\n")

	_, _ = io.WriteString(w, output.String())
}

func escapeLabelValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return strings.ReplaceAll(value, `"`, `\"`)
}
