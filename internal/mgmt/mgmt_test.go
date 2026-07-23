package mgmt

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/config"
)

func TestMetricsRequestCounters(t *testing.T) {
	metrics := NewMetrics("test")
	metrics.ObserveRequest("image", "", http.StatusOK, time.Millisecond)
	metrics.ObserveRequest("image", "", http.StatusOK, time.Millisecond)
	metrics.ObserveRequest("image", "", http.StatusNotFound, time.Millisecond)

	output := prometheusOutput(metrics)
	for _, want := range []string{
		`sinkhole_requests_total{kind="image",status="200"} 2`,
		`sinkhole_requests_total{kind="image",status="404"} 1`,
	} {
		if !hasLine(output, want) {
			t.Errorf("metrics output missing line %q:\n%s", want, output)
		}
	}
}

func TestMetricsHistogram(t *testing.T) {
	metrics := NewMetrics("test")
	metrics.ObserveRequest("image", "", http.StatusOK, 3*time.Millisecond)
	metrics.ObserveRequest("image", "", http.StatusOK, 50*time.Millisecond)
	metrics.ObserveRequest("image", "", http.StatusOK, 2*time.Second)
	output := prometheusOutput(metrics)

	for _, want := range []string{
		`sinkhole_request_duration_seconds_bucket{le="0.005"} 1`,
		`sinkhole_request_duration_seconds_bucket{le="0.1"} 2`,
		`sinkhole_request_duration_seconds_bucket{le="+Inf"} 3`,
		`sinkhole_request_duration_seconds_count 3`,
	} {
		if !hasLine(output, want) {
			t.Errorf("metrics output missing line %q:\n%s", want, output)
		}
	}

	gotSum := metricFloat(t, output, "sinkhole_request_duration_seconds_sum")
	if math.Abs(gotSum-2.053) > 0.000001 {
		t.Errorf("duration sum = %v, want approximately 2.053", gotSum)
	}

	var previous uint64
	for _, label := range durationLabels {
		prefix := `sinkhole_request_duration_seconds_bucket{le="` + label + `"}`
		value := metricUint(t, output, prefix)
		if value < previous {
			t.Fatalf("histogram bucket %q = %d, less than previous bucket %d", label, value, previous)
		}
		previous = value
	}
}

func TestObserveRequestCountsRuleHits(t *testing.T) {
	metrics := NewMetrics("test")
	metrics.ObserveRequest("script", "block-gpt", http.StatusOK, time.Millisecond)
	metrics.ObserveRequest("script", "block-gpt", http.StatusOK, time.Millisecond)
	metrics.ObserveRequest("image", "", http.StatusOK, time.Millisecond)

	snapshot := metrics.Snapshot()
	if snapshot.RequestsByRule["block-gpt"] != 2 {
		t.Fatalf("RequestsByRule[block-gpt] = %d, want 2", snapshot.RequestsByRule["block-gpt"])
	}
	if _, present := snapshot.RequestsByRule[""]; present {
		t.Fatal("empty rule name must not be counted")
	}
	var output strings.Builder
	metrics.WritePrometheus(&output)
	if !strings.Contains(output.String(), `sinkhole_rule_hits_total{rule="block-gpt"} 2`) {
		t.Fatalf("prometheus output missing rule counter:\n%s", output.String())
	}
}

func TestMetricsMetadataGaugesAndBuildInfo(t *testing.T) {
	metrics := NewMetrics("v1.2.3")
	metrics.SetRuleCount(7)
	metrics.SetLeafCacheSize(2)
	metrics.SetLeafCacheSize(9)
	output := prometheusOutput(metrics)

	families := map[string]string{
		"sinkhole_requests_total":           "counter",
		"sinkhole_rule_hits_total":          "counter",
		"sinkhole_request_duration_seconds": "histogram",
		"sinkhole_rules_loaded":             "gauge",
		"sinkhole_tls_leaf_cache_entries":   "gauge",
		"sinkhole_build_info":               "gauge",
	}
	for family, metricType := range families {
		if !strings.Contains(output, "# HELP "+family+" ") {
			t.Errorf("metrics output missing HELP for %s", family)
		}
		if !hasLine(output, "# TYPE "+family+" "+metricType) {
			t.Errorf("metrics output missing TYPE for %s", family)
		}
	}
	for _, want := range []string{
		"sinkhole_rules_loaded 7",
		"sinkhole_tls_leaf_cache_entries 9",
		`sinkhole_build_info{version="v1.2.3"} 1`,
	} {
		if !hasLine(output, want) {
			t.Errorf("metrics output missing line %q:\n%s", want, output)
		}
	}
}

func TestMetricsPrometheusOutputGolden(t *testing.T) {
	metrics := NewMetrics("v1\"test\\build\nnext")
	metrics.ObserveRequest("script", "", http.StatusNoContent, 6*time.Second)
	metrics.ObserveRequest("image", "", http.StatusNotFound, 5*time.Millisecond)
	metrics.ObserveRequest("image", "", http.StatusOK, 500*time.Microsecond)
	metrics.ObserveRequest("script", "", http.StatusOK, 25*time.Millisecond)
	metrics.SetRuleCount(7)
	metrics.SetLeafCacheSize(9)

	want := `# HELP sinkhole_requests_total Total sinkhole requests by response kind and HTTP status.
# TYPE sinkhole_requests_total counter
sinkhole_requests_total{kind="image",status="200"} 1
sinkhole_requests_total{kind="image",status="404"} 1
sinkhole_requests_total{kind="script",status="200"} 1
sinkhole_requests_total{kind="script",status="204"} 1
# HELP sinkhole_rule_hits_total Requests matched per configured rule.
# TYPE sinkhole_rule_hits_total counter
# HELP sinkhole_request_duration_seconds Sinkhole request duration in seconds.
# TYPE sinkhole_request_duration_seconds histogram
sinkhole_request_duration_seconds_bucket{le="0.001"} 1
sinkhole_request_duration_seconds_bucket{le="0.005"} 2
sinkhole_request_duration_seconds_bucket{le="0.025"} 3
sinkhole_request_duration_seconds_bucket{le="0.1"} 3
sinkhole_request_duration_seconds_bucket{le="0.5"} 3
sinkhole_request_duration_seconds_bucket{le="1"} 3
sinkhole_request_duration_seconds_bucket{le="5"} 3
sinkhole_request_duration_seconds_bucket{le="+Inf"} 4
sinkhole_request_duration_seconds_sum 6.0305
sinkhole_request_duration_seconds_count 4
# HELP sinkhole_rules_loaded Number of response rules currently loaded.
# TYPE sinkhole_rules_loaded gauge
sinkhole_rules_loaded 7
# HELP sinkhole_tls_leaf_cache_entries Number of entries in the TLS leaf certificate cache.
# TYPE sinkhole_tls_leaf_cache_entries gauge
sinkhole_tls_leaf_cache_entries 9
# HELP sinkhole_build_info Sinkhole responder build information.
# TYPE sinkhole_build_info gauge
sinkhole_build_info{version="v1\"test\\build\nnext"} 1
`
	if got := prometheusOutput(metrics); got != want {
		t.Fatalf("Prometheus output changed:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestMetricsSnapshotReflectsObservedValues(t *testing.T) {
	startedAt := time.Date(2026, time.July, 20, 12, 34, 56, 0, time.UTC)
	metrics := newMetrics("v2-test", func() time.Time { return startedAt })
	metrics.ObserveRequest("script", "", http.StatusNoContent, 6*time.Second)
	metrics.ObserveRequest("image", "", http.StatusNotFound, 5*time.Millisecond)
	metrics.ObserveRequest("image", "", http.StatusOK, 500*time.Microsecond)
	metrics.ObserveRequest("script", "", http.StatusOK, 25*time.Millisecond)
	metrics.SetRuleCount(7)
	metrics.SetLeafCacheSize(9)

	got := metrics.Snapshot()
	if got.Version != "v2-test" {
		t.Errorf("Snapshot().Version = %q, want %q", got.Version, "v2-test")
	}
	if !got.StartedAt.Equal(startedAt) {
		t.Errorf("Snapshot().StartedAt = %v, want %v", got.StartedAt, startedAt)
	}
	if want := map[string]uint64{"image": 2, "script": 2}; !reflect.DeepEqual(got.RequestsByKind, want) {
		t.Errorf("Snapshot().RequestsByKind = %#v, want %#v", got.RequestsByKind, want)
	}
	if want := map[int]uint64{http.StatusOK: 2, http.StatusNoContent: 1, http.StatusNotFound: 1}; !reflect.DeepEqual(got.RequestsByStatus, want) {
		t.Errorf("Snapshot().RequestsByStatus = %#v, want %#v", got.RequestsByStatus, want)
	}
	if got.RequestsTotal != 4 {
		t.Errorf("Snapshot().RequestsTotal = %d, want 4", got.RequestsTotal)
	}
	wantBuckets := []BucketCount{
		{LE: "0.001", Count: 1},
		{LE: "0.005", Count: 2},
		{LE: "0.025", Count: 3},
		{LE: "0.1", Count: 3},
		{LE: "0.5", Count: 3},
		{LE: "1", Count: 3},
		{LE: "5", Count: 3},
		{LE: "+Inf", Count: 4},
	}
	if !reflect.DeepEqual(got.DurationBuckets, wantBuckets) {
		t.Errorf("Snapshot().DurationBuckets = %#v, want %#v", got.DurationBuckets, wantBuckets)
	}
	if math.Abs(got.DurationSum-6.0305) > 0.0000001 {
		t.Errorf("Snapshot().DurationSum = %v, want approximately 6.0305", got.DurationSum)
	}
	if got.DurationCount != 4 {
		t.Errorf("Snapshot().DurationCount = %d, want 4", got.DurationCount)
	}
	if got.RulesLoaded != 7 {
		t.Errorf("Snapshot().RulesLoaded = %d, want 7", got.RulesLoaded)
	}
	if got.LeafCacheSize != 9 {
		t.Errorf("Snapshot().LeafCacheSize = %d, want 9", got.LeafCacheSize)
	}
}

func TestMetricsStartedAtUsesInjectedClock(t *testing.T) {
	want := time.Date(2026, time.July, 20, 1, 2, 3, 4, time.FixedZone("test", 90*60))
	metrics := newMetrics("test", func() time.Time { return want })

	if got := metrics.Snapshot().StartedAt; !got.Equal(want) {
		t.Fatalf("Snapshot().StartedAt = %v, want %v", got, want)
	}
}

func TestNilMetricsUpdatesDoNotPanic(t *testing.T) {
	var metrics *Metrics
	metrics.ObserveRequest("image", "", http.StatusOK, time.Second)
	metrics.SetRuleCount(1)
	metrics.SetLeafCacheSize(1)
}

func TestMetricsConcurrentAccess(t *testing.T) {
	metrics := NewMetrics("test")
	var writers sync.WaitGroup
	for range 100 {
		writers.Add(1)
		go func() {
			defer writers.Done()
			metrics.ObserveRequest("image", "", http.StatusOK, time.Millisecond)
		}()
	}

	var readers sync.WaitGroup
	for range 20 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 10 {
				metrics.WritePrometheus(io.Discard)
			}
		}()
	}
	writers.Wait()
	readers.Wait()

	if !hasLine(prometheusOutput(metrics), `sinkhole_requests_total{kind="image",status="200"} 100`) {
		t.Fatal("concurrent request count did not reach 100")
	}
}

func TestServeListenerEndpointsAndShutdown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	metrics := NewMetrics("integration")
	go func() {
		serveErr <- ServeListener(ctx, listener, metrics, testLogger())
	}()

	baseURL := "http://" + listener.Addr().String()
	response := requestEventually(t, http.MethodGet, baseURL+"/healthz")
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("GET /healthz = %d, content type %q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	var health map[string]string
	if err := json.NewDecoder(response.Body).Decode(&health); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	response.Body.Close()
	if health["status"] != "ok" {
		t.Fatalf("GET /healthz body = %v, want status ok", health)
	}

	response = requestEventually(t, http.MethodGet, baseURL+"/metrics")
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatalf("read metrics response: %v", err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != metricsContentType {
		t.Fatalf("GET /metrics = %d, content type %q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	if !strings.Contains(string(body), `sinkhole_build_info{version="integration"} 1`) {
		t.Fatalf("GET /metrics missing build info:\n%s", body)
	}

	response = requestEventually(t, http.MethodPost, baseURL+"/metrics")
	response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /metrics = %d, want 405", response.StatusCode)
	}
	response = requestEventually(t, http.MethodGet, baseURL+"/nope")
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("GET /nope = %d, want 404", response.StatusCode)
	}

	cancel()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("ServeListener() error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ServeListener did not stop within 3 seconds")
	}
}

func TestServeLoopbackGuard(t *testing.T) {
	tests := []struct {
		name          string
		address       string
		allowExternal bool
		wantError     bool
	}{
		{name: "IPv4 external", address: "0.0.0.0:9999", wantError: true},
		{name: "empty host", address: ":9999", wantError: true},
		{name: "hostname", address: "sinkhole.test:9999", wantError: true},
		{name: "localhost", address: "localhost:0"},
		{name: "IPv6 loopback", address: "[::1]:0"},
		{name: "external allowed", address: "0.0.0.0:0", allowExternal: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			cfg := &config.Config{Management: config.MgmtConfig{
				Listen:        tt.address,
				AllowExternal: tt.allowExternal,
			}}
			err := Serve(ctx, cfg, NewMetrics("test"), testLogger())
			if tt.wantError {
				if err == nil || !strings.Contains(err.Error(), "allow_external") {
					t.Fatalf("Serve() error = %v, want allow_external error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Serve() error = %v", err)
			}
		})
	}
}

func TestServeDisabledSkipsBind(t *testing.T) {
	disabled := false
	cfg := &config.Config{Management: config.MgmtConfig{
		Enabled: &disabled,
		Listen:  "256.0.0.1:1",
	}}
	if err := Serve(context.Background(), cfg, NewMetrics("test"), testLogger()); err != nil {
		t.Fatalf("Serve() error = %v, want nil", err)
	}
}

func TestServeReturnsBindFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	cfg := &config.Config{Management: config.MgmtConfig{Listen: listener.Addr().String()}}
	if err := Serve(context.Background(), cfg, NewMetrics("test"), testLogger()); err == nil {
		t.Fatal("Serve() error = nil, want bind failure")
	}
}

func prometheusOutput(metrics *Metrics) string {
	var output bytes.Buffer
	metrics.WritePrometheus(&output)
	return output.String()
}

func hasLine(output, want string) bool {
	for _, line := range strings.Split(output, "\n") {
		if line == want {
			return true
		}
	}
	return false
}

func metricFloat(t *testing.T, output, name string) float64 {
	t.Helper()
	value := metricValue(t, output, name)
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		t.Fatalf("parse %s value %q: %v", name, value, err)
	}
	return parsed
}

func metricUint(t *testing.T, output, name string) uint64 {
	t.Helper()
	value := metricValue(t, output, name)
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		t.Fatalf("parse %s value %q: %v", name, value, err)
	}
	return parsed
}

func metricValue(t *testing.T, output, name string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, name+" ") {
			return strings.TrimPrefix(line, name+" ")
		}
	}
	t.Fatalf("metrics output missing %q:\n%s", name, output)
	return ""
}

func requestEventually(t *testing.T, method, url string) *http.Response {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(2 * time.Second)
	for {
		request, err := http.NewRequest(method, url, nil)
		if err != nil {
			t.Fatalf("create request: %v", err)
		}
		response, err := client.Do(request)
		if err == nil {
			return response
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s %s: %v", method, url, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
