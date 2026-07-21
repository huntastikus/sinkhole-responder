package httpserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/config"
	"github.com/huntastikus/sinkhole-responder/internal/mgmt"
	"github.com/huntastikus/sinkhole-responder/internal/rules"
)

func TestAllowedMethods(t *testing.T) {
	server := httptest.NewServer(New(testConfig(), nil, discardLogger(), nil).Handler())
	defer server.Close()

	for _, method := range []string{
		http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete,
	} {
		t.Run(method, func(t *testing.T) {
			response := doRequest(t, server.Client(), method, server.URL+"/plain", nil)
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("%s status = %d, want 200", method, response.StatusCode)
			}
		})
	}

	t.Run("preflight", func(t *testing.T) {
		request, err := http.NewRequest(http.MethodOptions, server.URL+"/plain", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Access-Control-Request-Method", http.MethodPost)
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("preflight status = %d, want 204", response.StatusCode)
		}
	})

	t.Run("bare OPTIONS", func(t *testing.T) {
		response := doRequest(t, server.Client(), http.MethodOptions, server.URL+"/plain", nil)
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("bare OPTIONS status = %d, want 200", response.StatusCode)
		}
	})
}

func TestDisallowedMethod(t *testing.T) {
	server := httptest.NewServer(New(testConfig(), nil, discardLogger(), nil).Handler())
	defer server.Close()
	response := doRequest(t, server.Client(), http.MethodTrace, server.URL+"/", nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("TRACE status = %d, want 405", response.StatusCode)
	}
	if got := response.Header.Get("Allow"); got != allowedMethods {
		t.Fatalf("Allow = %q, want %q", got, allowedMethods)
	}
}

func TestRealServerResponseShapes(t *testing.T) {
	cfg := testConfig()
	cfg.Defaults.BeaconStatus = http.StatusNoContent
	server := httptest.NewServer(New(cfg, nil, discardLogger(), nil).Handler())
	defer server.Close()

	t.Run("beacon 204", func(t *testing.T) {
		response := doRequest(t, server.Client(), http.MethodGet, server.URL+"/unknown", nil)
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusNoContent || response.Header.Get("Content-Type") != "" || len(body) != 0 {
			t.Fatalf("beacon = status %d, Content-Type %q, body %q", response.StatusCode, response.Header.Get("Content-Type"), body)
		}
	})

	t.Run("HEAD gif", func(t *testing.T) {
		response := doRequest(t, server.Client(), http.MethodHead, server.URL+"/x.gif", nil)
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK || response.ContentLength != 43 || len(body) != 0 || response.Header.Get("Content-Type") != "image/gif" {
			t.Fatalf("HEAD gif = status %d, length %d, type %q, body len %d", response.StatusCode, response.ContentLength, response.Header.Get("Content-Type"), len(body))
		}
	})

	t.Run("JavaScript headers", func(t *testing.T) {
		response := doRequest(t, server.Client(), http.MethodGet, server.URL+"/x.js", nil)
		response.Body.Close()
		want := map[string]string{
			"Access-Control-Allow-Origin":  "*",
			"Cross-Origin-Resource-Policy": "cross-origin",
			"Timing-Allow-Origin":          "*",
			"Cache-Control":                "no-store",
			"X-Sinkhole":                   "1",
		}
		for header, value := range want {
			if got := response.Header.Get(header); got != value {
				t.Errorf("%s = %q, want %q", header, got, value)
			}
		}
	})
}

func TestRuleIntegration(t *testing.T) {
	cfg := testConfig()
	engine := compileRules(t, []rules.Rule{{
		Name:     "blocked-example",
		HostGlob: "*.example.test",
		Response: rules.Response{Status: http.StatusTeapot, ContentType: "text/custom", Body: "custom"},
	}})
	server := httptest.NewServer(New(cfg, engine, discardLogger(), nil).Handler())
	defer server.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL+"/asset", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "ads.example.test"
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusTeapot || string(body) != "custom" || response.Header.Get("Content-Type") != "text/custom" {
		t.Fatalf("matched response = %d, %q, %q", response.StatusCode, body, response.Header.Get("Content-Type"))
	}

	request, err = http.NewRequest(http.MethodGet, server.URL+"/x.js", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "other.test"
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/javascript" {
		t.Fatalf("non-match = %d, %q", response.StatusCode, response.Header.Get("Content-Type"))
	}
}

func TestBodyLimit(t *testing.T) {
	cfg := testConfig()
	cfg.Limits.MaxBodyBytes = 1024
	server := httptest.NewServer(New(cfg, nil, discardLogger(), nil).Handler())
	defer server.Close()

	response := doRequest(t, server.Client(), http.MethodPost, server.URL+"/", strings.NewReader(strings.Repeat("x", 4096)))
	response.Body.Close()
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized POST status = %d, want 413", response.StatusCode)
	}
}

func TestCompliantBodyKeepsConnectionReusable(t *testing.T) {
	cfg := testConfig()
	cfg.Limits.MaxBodyBytes = 1024
	server := httptest.NewServer(New(cfg, nil, discardLogger(), nil).Handler())
	defer server.Close()

	client := server.Client()
	first := doRequest(t, client, http.MethodPost, server.URL+"/", strings.NewReader(strings.Repeat("x", 512)))
	_, _ = io.Copy(io.Discard, first.Body)
	first.Body.Close()

	reused := false
	request, err := http.NewRequest(http.MethodGet, server.URL+"/x.js", nil)
	if err != nil {
		t.Fatal(err)
	}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused },
	}))
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if !reused {
		t.Fatal("second request did not reuse the compliant POST connection")
	}
}

func TestRateLimit(t *testing.T) {
	cfg := testConfig()
	cfg.Limits.RatePerIP = 5
	cfg.Limits.RateBurst = 5
	handler := New(cfg, nil, discardLogger(), nil).Handler()

	for i := range 6 {
		request := httptest.NewRequest(http.MethodGet, "http://example.test/x.js", nil)
		request.RemoteAddr = "192.0.2.10:1234"
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		want := http.StatusOK
		if i == 5 {
			want = http.StatusTooManyRequests
		}
		if recorder.Code != want {
			t.Fatalf("request %d status = %d, want %d", i+1, recorder.Code, want)
		}
		if i == 5 && recorder.Header().Get("Retry-After") != "1" {
			t.Fatalf("Retry-After = %q, want 1", recorder.Header().Get("Retry-After"))
		}
	}

	request := httptest.NewRequest(http.MethodGet, "http://example.test/x.js", nil)
	request.RemoteAddr = "192.0.2.11:1234"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("different client status = %d, want 200", recorder.Code)
	}
}

func TestDisabledRateLimit(t *testing.T) {
	cfg := testConfig()
	cfg.Limits.RatePerIP = 0
	handler := New(cfg, nil, discardLogger(), nil).Handler()
	for range 100 {
		request := httptest.NewRequest(http.MethodGet, "http://example.test/x.js", nil)
		request.RemoteAddr = "192.0.2.10:1234"
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d with rate limiting disabled", recorder.Code)
		}
	}
}

func TestRecoverMiddleware(t *testing.T) {
	var logs bytes.Buffer
	server := New(testConfig(), nil, slog.New(slog.NewJSONHandler(&logs, nil)), nil)
	handler := recoverMiddleware(server, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://example.test/", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("panic status = %d, want 500", recorder.Code)
	}
	if !strings.Contains(logs.String(), "boom") || !strings.Contains(logs.String(), "stack") {
		t.Fatalf("panic log missing panic or stack: %s", logs.String())
	}
}

func TestRecoverMiddlewareRepanicsAbortHandler(t *testing.T) {
	server := New(testConfig(), nil, discardLogger(), nil)
	handler := recoverMiddleware(server, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	}))

	defer func() {
		if recovered := recover(); recovered != http.ErrAbortHandler {
			t.Fatalf("recovered = %v, want http.ErrAbortHandler", recovered)
		}
	}()
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test/", nil))
}

func TestAccessLogFieldsAndQueryPrivacy(t *testing.T) {
	var output bytes.Buffer
	cfg := testConfig()
	server := New(cfg, nil, slog.New(slog.NewJSONHandler(&output, nil)), nil)
	request := httptest.NewRequest(http.MethodGet, "http://EXAMPLE.test:8080/x.js?token=secret", nil)
	request.RemoteAddr = "203.0.113.77:1234"
	server.Handler().ServeHTTP(httptest.NewRecorder(), request)

	entry := decodeLog(t, output.Bytes())
	for key, want := range map[string]any{
		"host":   "example.test",
		"path":   "/x.js",
		"kind":   "script",
		"status": float64(http.StatusOK),
		"client": "203.0.113.0/24",
	} {
		if got := entry[key]; got != want {
			t.Errorf("log %s = %#v, want %#v", key, got, want)
		}
	}
	if _, ok := entry["duration_ms"].(float64); !ok {
		t.Errorf("duration_ms missing or non-numeric: %#v", entry["duration_ms"])
	}
	if _, ok := entry["query"]; ok || strings.Contains(output.String(), "token") || strings.Contains(output.String(), "secret") {
		t.Fatalf("private query leaked into log: %s", output.String())
	}
}

func TestAccessLogOptionsAndAnonymization(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		configure  func(*config.Config)
		wantClient string
		wantQuery  bool
		wantEmpty  bool
	}{
		{name: "IPv6 anonymized", remoteAddr: "[2001:db8:aa:bb::1]:443", wantClient: "2001:db8:aa::/48"},
		{name: "full IP", remoteAddr: "203.0.113.77:1234", configure: func(cfg *config.Config) { cfg.Logging.AnonymizeClient = boolPointer(false) }, wantClient: "203.0.113.77"},
		{name: "query enabled", remoteAddr: "203.0.113.77:1234", configure: func(cfg *config.Config) { cfg.Logging.LogQuery = true }, wantClient: "203.0.113.0/24", wantQuery: true},
		{name: "access disabled", remoteAddr: "203.0.113.77:1234", configure: func(cfg *config.Config) { cfg.Logging.AccessLog = boolPointer(false) }, wantEmpty: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			cfg := testConfig()
			if tt.configure != nil {
				tt.configure(cfg)
			}
			request := httptest.NewRequest(http.MethodGet, "http://example.test/x.js?token=secret", nil)
			request.RemoteAddr = tt.remoteAddr
			New(cfg, nil, slog.New(slog.NewJSONHandler(&output, nil)), nil).Handler().ServeHTTP(httptest.NewRecorder(), request)
			if tt.wantEmpty {
				if output.Len() != 0 {
					t.Fatalf("access log disabled, got %s", output.String())
				}
				return
			}
			entry := decodeLog(t, output.Bytes())
			if entry["client"] != tt.wantClient {
				t.Errorf("client = %v, want %q", entry["client"], tt.wantClient)
			}
			_, hasQuery := entry["query"]
			if hasQuery != tt.wantQuery {
				t.Errorf("query present = %v, want %v", hasQuery, tt.wantQuery)
			}
		})
	}
}

func TestMetricsObserveResponse(t *testing.T) {
	metrics := mgmt.NewMetrics("test")
	cfg := testConfig()
	cfg.Logging.AccessLog = boolPointer(false)
	handler := New(cfg, nil, discardLogger(), metrics).Handler()
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test/x.js", nil))

	var output strings.Builder
	metrics.WritePrometheus(&output)
	if !strings.Contains(output.String(), `sinkhole_requests_total{kind="script",status="200"} 1`) {
		t.Fatalf("metrics missing script response:\n%s", output.String())
	}
}

func TestSwapConfig(t *testing.T) {
	base := testConfig()
	server := New(base, nil, discardLogger(), nil)
	request := httptest.NewRequest(http.MethodGet, "http://ads.example.test/item", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("before swap status = %d", recorder.Code)
	}

	updated := testConfig()
	engine := compileRules(t, []rules.Rule{{
		Name: "live", Host: "ads.example.test",
		Response: rules.Response{Status: http.StatusForbidden, Body: "blocked"},
	}})
	server.SwapConfig(updated, engine)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://ads.example.test/item", nil))
	if recorder.Code != http.StatusForbidden || recorder.Body.String() != "blocked" {
		t.Fatalf("after swap = %d, %q", recorder.Code, recorder.Body.String())
	}

	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				recorder := httptest.NewRecorder()
				server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://ads.example.test/item", nil))
			}
		}()
	}
	for range 100 {
		server.SwapConfig(base, nil)
		server.SwapConfig(updated, engine)
	}
	workers.Wait()
}

func TestStartRequiresListener(t *testing.T) {
	cfg := testConfig()
	cfg.Listen.HTTP = nil
	if err := New(cfg, nil, discardLogger(), nil).Start(context.Background()); err == nil {
		t.Fatal("Start() with no listeners returned nil")
	}
}

func TestStartPublishesBoundAddrs(t *testing.T) {
	server := New(testConfig(), nil, discardLogger(), nil)
	if got := server.Addrs(); len(got) != 0 {
		t.Fatalf("Addrs() before Start = %v, want empty", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Start(ctx) }()

	var addrs []net.Addr
	deadline := time.Now().Add(time.Second)
	for len(addrs) == 0 && time.Now().Before(deadline) {
		addrs = server.Addrs()
		time.Sleep(time.Millisecond)
	}
	if len(addrs) != 1 {
		cancel()
		<-done
		t.Fatalf("Addrs() after Start = %v, want one address", addrs)
	}
	if _, port, err := net.SplitHostPort(addrs[0].String()); err != nil || port == "0" {
		cancel()
		<-done
		t.Fatalf("bound address = %q, want allocated port (error %v)", addrs[0], err)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Start() = %v", err)
	}
}

func TestStartAndTLSListenersPublishCombinedAddrs(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	tlsConfig := &tls.Config{
		Certificates: append([]tls.Certificate(nil), fixture.TLS.Certificates...),
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	fixture.Close()

	tlsListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := New(testConfig(), nil, discardLogger(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	results := make(chan error, 2)
	go func() { results <- server.Start(ctx) }()
	go func() { results <- server.StartTLSListeners(ctx, []net.Listener{tlsListener}, tlsConfig) }()

	var addrs []net.Addr
	deadline := time.Now().Add(time.Second)
	for len(addrs) != 2 && time.Now().Before(deadline) {
		addrs = server.Addrs()
		time.Sleep(time.Millisecond)
	}
	if len(addrs) != 2 {
		cancel()
		<-results
		<-results
		t.Fatalf("combined Addrs() = %v, want HTTP and HTTPS addresses", addrs)
	}

	cancel()
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("server shutdown = %v", err)
		}
	}
}

func TestStartGracefulShutdown(t *testing.T) {
	cfg := testConfig()
	engine := compileRules(t, []rules.Rule{{
		Name: "slow", PathGlob: "/slow",
		Response: rules.Response{Status: http.StatusOK, Body: "done", DelayMS: 200},
	}})
	server := New(cfg, engine, discardLogger(), nil)
	originalHandler := server.handler
	requestStarted := make(chan struct{})
	var startedOnce sync.Once
	server.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedOnce.Do(func() { close(requestStarted) })
		originalHandler.ServeHTTP(w, r)
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Start(ctx) }()

	var addrs []net.Addr
	deadline := time.Now().Add(time.Second)
	for len(addrs) == 0 && time.Now().Before(deadline) {
		addrs = server.Addrs()
		time.Sleep(time.Millisecond)
	}
	if len(addrs) != 1 {
		cancel()
		<-done
		t.Fatalf("Addrs() after Start = %v, want one address", addrs)
	}
	address := addrs[0].String()

	url := "http://" + address + "/slow"
	responseDone := make(chan error, 1)
	go func() {
		response, err := (&http.Client{Timeout: 2 * time.Second}).Get(url)
		if err != nil {
			responseDone <- err
			return
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil {
			responseDone <- readErr
			return
		}
		if response.StatusCode != http.StatusOK || string(body) != "done" {
			responseDone <- fmt.Errorf("slow response = %d, %q", response.StatusCode, body)
			return
		}
		responseDone <- nil
	}()

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("slow request did not reach the handler")
	}
	started := time.Now()
	cancel()
	if err := <-responseDone; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start() = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return within 3 seconds")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("shutdown took %v", elapsed)
	}

	connection, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
	if err == nil {
		connection.Close()
		t.Fatal("listener accepted a connection after shutdown")
	}
}

func TestMalformedAndOversizedHostHeaders(t *testing.T) {
	cfg := testConfig()
	cfg.Limits.MaxHeaderBytes = 1024
	server := New(cfg, nil, discardLogger(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Start(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Start() = %v", err)
		}
	}()

	var addrs []net.Addr
	deadline := time.Now().Add(time.Second)
	for len(addrs) == 0 && time.Now().Before(deadline) {
		addrs = server.Addrs()
		time.Sleep(time.Millisecond)
	}
	if len(addrs) != 1 {
		t.Fatalf("Addrs() after Start = %v, want one address", addrs)
	}
	address := addrs[0].String()

	status := rawRequestStatus(t, address, "GET / HTTP/1.1\r\nHost: [::bad\r\nConnection: close\r\n\r\n")
	if status < 200 || status > 499 {
		t.Fatalf("malformed Host status = %d, want 2xx-4xx", status)
	}

	garbage := strings.Repeat("x", 16*1024)
	status = rawRequestStatus(t, address, "GET / HTTP/1.1\r\nHost: example.test\r\nX-Garbage: "+garbage+"\r\n\r\n")
	if status != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("oversized header status = %d, want 431", status)
	}
}

func TestClientLimitersPreserveMaximumClientCount(t *testing.T) {
	var limiters clientLimiters
	limiters.configure(1_000_000, 1)
	for i := range maxClients + evictionBatchSize {
		limiters.allow(fmt.Sprintf("client-%d", i))
		if len(limiters.clients) > maxClients {
			t.Fatalf("client count = %d, exceeds maximum %d", len(limiters.clients), maxClients)
		}
	}
}

func testConfig() *config.Config {
	return &config.Config{
		Listen: config.ListenConfig{HTTP: []string{"127.0.0.1:0"}},
		Defaults: config.DefaultsConfig{
			Status:        http.StatusOK,
			BeaconStatus:  http.StatusOK,
			MediaResponse: "204",
			CacheControl:  "no-store",
		},
		Limits: config.LimitsConfig{
			MaxHeaderBytes: 16 * 1024,
			MaxBodyBytes:   64 * 1024,
			ReadTimeout:    2 * time.Second,
			WriteTimeout:   2 * time.Second,
			IdleTimeout:    5 * time.Second,
			RateBurst:      50,
		},
		Logging: config.LoggingConfig{
			AccessLog:       boolPointer(true),
			AnonymizeClient: boolPointer(true),
		},
		JSONP: config.JSONPConfig{Param: "callback"},
	}
}

func compileRules(t *testing.T, configured []rules.Rule) *rules.Engine {
	t.Helper()
	engine, err := rules.Compile(configured, t.TempDir())
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	return engine
}

func boolPointer(value bool) *bool { return &value }

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func doRequest(t *testing.T, client *http.Client, method, url string, body io.Reader) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func decodeLog(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("decode log %q: %v", data, err)
	}
	return entry
}

func rawRequestStatus(t *testing.T, address, request string) int {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		t.Fatalf("invalid status line %q", line)
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("parse status line %q: %v", line, err)
	}
	return status
}
