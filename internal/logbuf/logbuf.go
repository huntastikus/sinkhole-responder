package logbuf

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

const defaultCapacity = 500

// Record is a log entry retained by a Ring.
type Record struct {
	Time  time.Time
	Level string
	Msg   string
	Attrs map[string]any
}

type entry struct {
	record Record
	level  slog.Level
}

// Ring is a fixed-size, concurrency-safe log buffer.
type Ring struct {
	mu       sync.RWMutex
	entries  []entry
	start    int
	size     int
	capacity int
}

// NewRing creates a ring with the requested capacity. Non-positive capacities
// use a default of 500 records.
func NewRing(capacity int) *Ring {
	if capacity <= 0 {
		capacity = defaultCapacity
	}
	return &Ring{
		entries:  make([]entry, capacity),
		capacity: capacity,
	}
}

// Handler returns a slog handler that stores records in the ring and forwards
// them to next.
func (r *Ring) Handler(next slog.Handler) slog.Handler {
	return &handler{ring: r, next: next}
}

// Snapshot returns up to limit matching records in newest-first order.
func (r *Ring) Snapshot(minLevel slog.Level, limit int) []Record {
	if limit <= 0 {
		return []Record{}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Record, 0, min(limit, r.size))
	for offset := r.size - 1; offset >= 0 && len(result) < limit; offset-- {
		item := r.entries[(r.start+offset)%r.capacity]
		if item.level < minLevel {
			continue
		}
		item.record.Attrs = cloneAttrs(item.record.Attrs)
		result = append(result, item.record)
	}
	return result
}

func (r *Ring) append(item entry) {
	r.mu.Lock()
	defer r.mu.Unlock()

	index := (r.start + r.size) % r.capacity
	if r.size == r.capacity {
		index = r.start
		r.start = (r.start + 1) % r.capacity
	} else {
		r.size++
	}
	r.entries[index] = item
}

type scopedAttr struct {
	groups []string
	attr   slog.Attr
}

type handler struct {
	ring   *Ring
	next   slog.Handler
	attrs  []scopedAttr
	groups []string
}

func (h *handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *handler) Handle(ctx context.Context, record slog.Record) error {
	attrs := make(map[string]any)
	for _, item := range h.attrs {
		addAttr(attrs, item.groups, item.attr)
	}
	record.Attrs(func(attr slog.Attr) bool {
		addAttr(attrs, h.groups, attr)
		return true
	})

	h.ring.append(entry{
		level: record.Level,
		record: Record{
			Time:  record.Time,
			Level: record.Level.String(),
			Msg:   record.Message,
			Attrs: attrs,
		},
	})

	return h.next.Handle(ctx, record)
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	contextAttrs := append([]scopedAttr(nil), h.attrs...)
	for _, attr := range attrs {
		contextAttrs = append(contextAttrs, scopedAttr{
			groups: append([]string(nil), h.groups...),
			attr:   attr,
		})
	}
	return &handler{
		ring:   h.ring,
		next:   h.next.WithAttrs(attrs),
		attrs:  contextAttrs,
		groups: append([]string(nil), h.groups...),
	}
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	groups := append([]string(nil), h.groups...)
	groups = append(groups, name)
	return &handler{
		ring:   h.ring,
		next:   h.next.WithGroup(name),
		attrs:  append([]scopedAttr(nil), h.attrs...),
		groups: groups,
	}
}

func addAttr(attrs map[string]any, groups []string, attr slog.Attr) {
	value := attr.Value.Resolve()
	if len(groups) == 0 && value.Kind() != slog.KindGroup {
		attr.Value = value
		addAttrValue(attrs, attr)
		return
	}
	materialized := make(map[string]any)
	if !addAttrValue(materialized, attr) {
		return
	}

	target := attrs
	for _, group := range groups {
		nested, ok := target[group].(map[string]any)
		if !ok {
			nested = make(map[string]any)
			target[group] = nested
		}
		target = nested
	}
	for key, value := range materialized {
		target[key] = value
	}
}

func addAttrValue(target map[string]any, attr slog.Attr) bool {
	value := attr.Value.Resolve()
	if attr.Key == "" && value.Kind() == slog.KindAny && value.Any() == nil {
		return false
	}

	if value.Kind() != slog.KindGroup {
		target[attr.Key] = value.Any()
		return true
	}

	nested := make(map[string]any)
	for _, child := range value.Group() {
		addAttrValue(nested, child)
	}
	if len(nested) == 0 {
		return false
	}
	if attr.Key == "" {
		for key, child := range nested {
			target[key] = child
		}
		return true
	}
	target[attr.Key] = nested
	return true
}

func cloneAttrs(attrs map[string]any) map[string]any {
	clone := make(map[string]any, len(attrs))
	for key, value := range attrs {
		if nested, ok := value.(map[string]any); ok {
			clone[key] = cloneAttrs(nested)
			continue
		}
		clone[key] = value
	}
	return clone
}
