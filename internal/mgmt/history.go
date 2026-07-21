package mgmt

import (
	"context"
	"sync"
	"time"
)

const (
	fineCapacity   = 300
	coarseCapacity = 180
)

var statusClasses = [...]string{"2xx", "3xx", "4xx", "5xx"}

// Sample is one point in a metrics history series.
type Sample struct {
	T             time.Time
	RPS           float64
	ByStatusClass map[string]float64
	LeafCache     int64
}

// History stores bounded fine- and coarse-grained metrics series in memory.
type History struct {
	mu     sync.RWMutex
	fine   sampleRing
	coarse sampleRing
}

// NewHistory returns an empty metrics history.
func NewHistory() *History {
	return &History{
		fine:   newSampleRing(fineCapacity),
		coarse: newSampleRing(coarseCapacity),
	}
}

// Record computes rates between two snapshots and appends a timestamped fine sample.
func (h *History) Record(prev, cur Snapshot, interval time.Duration, stamp time.Time) {
	h.recordAt(prev, cur, interval, stamp)
}

func (h *History) recordAt(prev, cur Snapshot, interval time.Duration, stamp time.Time) Sample {
	sample := sampleFromSnapshots(prev, cur, interval, stamp)
	h.mu.Lock()
	h.fine.append(sample)
	h.mu.Unlock()
	return sample
}

// Series returns a copy of a history series in oldest-to-newest order. The 3h
// range selects coarse samples; 5m and all other values select fine samples.
func (h *History) Series(rng string) []Sample {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if rng == "3h" {
		return h.coarse.snapshot()
	}
	return h.fine.snapshot()
}

// RunSampler records a fine sample on each tick and a coarse aggregate after
// each accumulated minute of fine intervals. It returns when ctx is canceled.
func RunSampler(ctx context.Context, m *Metrics, h *History, fine time.Duration) {
	if h == nil || fine <= 0 {
		return
	}

	ticker := time.NewTicker(fine)
	defer ticker.Stop()

	prev := m.Snapshot()
	var elapsed time.Duration
	minuteSamples := make([]Sample, 0, minuteSampleCapacity(fine))
	for {
		select {
		case <-ctx.Done():
			return
		case stamp := <-ticker.C:
			cur := m.Snapshot()
			sample := h.recordAt(prev, cur, fine, stamp)
			prev = cur
			minuteSamples = append(minuteSamples, sample)
			elapsed += fine
			if elapsed >= time.Minute {
				h.recordCoarse(minuteSamples)
				minuteSamples = minuteSamples[:0]
				elapsed %= time.Minute
			}
		}
	}
}

func minuteSampleCapacity(fine time.Duration) int {
	count := int(time.Minute / fine)
	if count < 1 {
		return 1
	}
	return count
}

func sampleFromSnapshots(prev, cur Snapshot, interval time.Duration, stamp time.Time) Sample {
	seconds := interval.Seconds()
	sample := Sample{
		T:             stamp,
		ByStatusClass: zeroStatusRates(),
		LeafCache:     cur.LeafCacheSize,
	}
	if seconds <= 0 {
		return sample
	}

	sample.RPS = counterRate(prev.RequestsTotal, cur.RequestsTotal, seconds)
	for status, current := range cur.RequestsByStatus {
		class := status / 100
		if class < 2 || class > 5 {
			continue
		}
		key := statusClasses[class-2]
		sample.ByStatusClass[key] += counterRate(prev.RequestsByStatus[status], current, seconds)
	}
	return sample
}

func counterRate(previous, current uint64, seconds float64) float64 {
	if current < previous {
		return 0
	}
	return float64(current-previous) / seconds
}

func zeroStatusRates() map[string]float64 {
	rates := make(map[string]float64, len(statusClasses))
	for _, class := range statusClasses {
		rates[class] = 0
	}
	return rates
}

func (h *History) recordCoarse(samples []Sample) {
	if len(samples) == 0 {
		return
	}

	aggregate := Sample{
		T:             samples[len(samples)-1].T,
		ByStatusClass: zeroStatusRates(),
		LeafCache:     samples[len(samples)-1].LeafCache,
	}
	for _, sample := range samples {
		aggregate.RPS += sample.RPS
		for class, rate := range sample.ByStatusClass {
			aggregate.ByStatusClass[class] += rate
		}
	}
	count := float64(len(samples))
	aggregate.RPS /= count
	for class, total := range aggregate.ByStatusClass {
		aggregate.ByStatusClass[class] = total / count
	}

	h.mu.Lock()
	h.coarse.append(aggregate)
	h.mu.Unlock()
}

type sampleRing struct {
	values []Sample
	next   int
}

func newSampleRing(capacity int) sampleRing {
	return sampleRing{values: make([]Sample, 0, capacity)}
}

func (r *sampleRing) append(sample Sample) {
	sample = cloneSample(sample)
	if len(r.values) < cap(r.values) {
		r.values = append(r.values, sample)
		return
	}
	r.values[r.next] = sample
	r.next = (r.next + 1) % cap(r.values)
}

func (r *sampleRing) snapshot() []Sample {
	result := make([]Sample, len(r.values))
	for i := range r.values {
		index := i
		if len(r.values) == cap(r.values) {
			index = (r.next + i) % len(r.values)
		}
		result[i] = cloneSample(r.values[index])
	}
	return result
}

func cloneSample(sample Sample) Sample {
	clone := sample
	clone.ByStatusClass = make(map[string]float64, len(sample.ByStatusClass))
	for class, rate := range sample.ByStatusClass {
		clone.ByStatusClass[class] = rate
	}
	return clone
}
