package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/admin"
	"github.com/huntastikus/sinkhole-responder/internal/config"
	"github.com/huntastikus/sinkhole-responder/internal/mgmt"
	"github.com/huntastikus/sinkhole-responder/internal/rules"
	"github.com/huntastikus/sinkhole-responder/internal/state"
	"github.com/huntastikus/sinkhole-responder/internal/tlsx"
)

func TestRunLifecycleAndGracefulShutdown(t *testing.T) {
	cfg := testConfig(t)
	cfg.Rules = []rules.Rule{{
		Name:     "slow",
		PathGlob: "/slow",
		Response: rules.Response{Status: http.StatusOK, Body: "done", DelayMS: 200},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan []net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, "test", discardLogger(), nil, nil, WithReadyFunc(func(addrs []net.Addr) {
			ready <- addrs
		}))
	}()
	defer cancel()

	baseURL := readyURL(t, ready, done)
	client := &http.Client{Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()

	response, err := client.Get(baseURL + "/x.gif")
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "image/gif" {
		t.Fatalf("GIF response = %d, %q", response.StatusCode, response.Header.Get("Content-Type"))
	}

	wroteRequest := make(chan struct{})
	slowDone := make(chan error, 1)
	request, err := http.NewRequest(http.MethodGet, baseURL+"/slow", nil)
	if err != nil {
		t.Fatal(err)
	}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) { close(wroteRequest) },
	}))
	go func() {
		response, err := client.Do(request)
		if err != nil {
			slowDone <- err
			return
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil {
			slowDone <- readErr
			return
		}
		if response.StatusCode != http.StatusOK || string(body) != "done" {
			slowDone <- fmt.Errorf("slow response = %d, %q", response.StatusCode, body)
			return
		}
		slowDone <- nil
	}()

	select {
	case <-wroteRequest:
	case <-time.After(time.Second):
		t.Fatal("slow request was not written")
	}
	time.Sleep(25 * time.Millisecond)
	cancel()

	if err := <-slowDone; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3 seconds")
	}
}

func TestRunMergesEnabledRulepacks(t *testing.T) {
	cfg := testConfig(t)
	cfg.Rulepacks.Enabled = []string{"recommended"}
	cfg.Rules = nil

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan []net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, "test", discardLogger(), nil, nil, WithReadyFunc(func(addrs []net.Addr) {
			ready <- addrs
		}))
	}()
	defer cancel()

	baseURL := readyURL(t, ready, done)
	request, err := http.NewRequest(http.MethodGet, baseURL+"/tag/js/gpt.js", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "securepubads.g.doubleclick.net"
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if got := response.Header.Get("Content-Type"); got != "application/javascript" {
		t.Errorf("Content-Type = %q, want application/javascript", got)
	}
	if !bytes.Contains(body, []byte("googletag")) {
		t.Errorf("body = %q, want stub-gpt body containing googletag", body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3 seconds")
	}
}

func TestRunRejectsUnknownRulepack(t *testing.T) {
	cfg := testConfig(t)
	cfg.Rulepacks.Enabled = []string{"nope"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := Run(ctx, cfg, "test", discardLogger(), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "rulepack") {
		t.Fatalf("Run() = %v, want rulepack merge error", err)
	}
}

func TestRunAdminEnabledServesSetupAndShutsDown(t *testing.T) {
	cfg := testConfig(t)
	cfg.StateDir = t.TempDir()
	cfg.Admin = config.AdminConfig{
		Enabled:    true,
		Listen:     reservedTCPAddress(t, "127.0.0.1"),
		SessionTTL: time.Hour,
		LoginBurst: 5,
	}

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan []net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, "test", discardLogger(), nil, nil, WithReadyFunc(func(addrs []net.Addr) {
			ready <- addrs
		}))
	}()
	defer cancel()

	readyURL(t, ready, done)
	waitForHTTPStatus(t, "http://"+cfg.Admin.Listen+"/setup", http.StatusOK)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3 seconds")
	}
}

func TestRunStartsSamplerWhenAdminEnabled(t *testing.T) {
	cfg := testConfig(t)
	cfg.StateDir = t.TempDir()
	cfg.Admin = config.AdminConfig{
		Enabled:    true,
		Listen:     reservedTCPAddress(t, "127.0.0.1"),
		SessionTTL: time.Hour,
		LoginBurst: 5,
	}
	h := mgmt.NewHistory()

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan []net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, "test", discardLogger(), nil, nil,
			WithReadyFunc(func(addrs []net.Addr) {
				ready <- addrs
			}),
			WithMetricsHistory(h),
			WithSamplerInterval(2*time.Millisecond),
		)
	}()
	defer cancel()

	readyURL(t, ready, done)
	deadline := time.Now().Add(1500 * time.Millisecond)
	for len(h.Series("5m")) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(h.Series("5m")) == 0 {
		t.Fatal("metrics history did not populate within 1.5 seconds")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3 seconds")
	}
}

func TestRunRestoresPersistedMetricsAcrossRestart(t *testing.T) {
	cfg := testConfig(t)
	cfg.StateDir = t.TempDir()
	cfg.Admin = config.AdminConfig{
		Enabled:    true,
		Listen:     reservedTCPAddress(t, "127.0.0.1"),
		SessionTTL: time.Hour,
		LoginBurst: 5,
	}
	cfg.Rules = []rules.Rule{{
		Name:     "persisted-rule",
		PathGlob: "/persisted",
		Response: rules.Response{Status: http.StatusNoContent},
	}}

	runOnce := func(request bool) {
		ctx, cancel := context.WithCancel(context.Background())
		ready := make(chan []net.Addr, 1)
		done := make(chan error, 1)
		go func() {
			done <- Run(ctx, cfg, "test", discardLogger(), nil, nil, WithReadyFunc(func(addrs []net.Addr) {
				ready <- addrs
			}))
		}()
		baseURL := readyURL(t, ready, done)
		if request {
			response, err := http.Get(baseURL + "/persisted")
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNoContent)
			}
		}
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Run() = %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Run did not return within 3 seconds")
		}
	}

	runOnce(true)
	runOnce(false)

	data, err := os.ReadFile(filepath.Join(cfg.StateDir, "metrics", "state.json"))
	if err != nil {
		t.Fatalf("read persisted metrics: %v", err)
	}
	metrics := mgmt.NewMetrics("verification")
	history := mgmt.NewHistory()
	if err := mgmt.RestoreState(metrics, history, data); err != nil {
		t.Fatalf("restore persisted metrics: %v", err)
	}
	snapshot := metrics.Snapshot()
	if snapshot.RequestsTotal != 1 || snapshot.RequestsByRule["persisted-rule"] != 1 {
		t.Fatalf("restored snapshot = %+v, want one persisted rule request", snapshot)
	}
}

func TestRunSkipsSamplerWhenAdminDisabled(t *testing.T) {
	cfg := testConfig(t)
	h := mgmt.NewHistory()

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan []net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, "test", discardLogger(), nil, nil,
			WithReadyFunc(func(addrs []net.Addr) {
				ready <- addrs
			}),
			WithMetricsHistory(h),
			WithSamplerInterval(2*time.Millisecond),
		)
	}()
	defer cancel()

	readyURL(t, ready, done)
	time.Sleep(60 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3 seconds")
	}
	if got := len(h.Series("5m")); got != 0 {
		t.Fatalf("metrics history samples = %d, want 0", got)
	}
}

func TestRunAdminDisabledPreservesV1Behavior(t *testing.T) {
	cfg := testConfig(t)
	stateDir := filepath.Join(t.TempDir(), "must-not-exist")
	adminAddress := reservedTCPAddress(t, "127.0.0.1")
	cfg.StateDir = stateDir
	cfg.Admin.Listen = adminAddress

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan []net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, "test", discardLogger(), nil, nil, WithReadyFunc(func(addrs []net.Addr) {
			ready <- addrs
		}))
	}()
	defer cancel()

	readyURL(t, ready, done)
	connection, err := net.DialTimeout("tcp", adminAddress, 100*time.Millisecond)
	if err == nil {
		connection.Close()
		t.Fatalf("admin listener %s is open while admin is disabled", adminAddress)
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("state directory stat error = %v, want not-exist", err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3 seconds")
	}
}

func TestRunAdminStateCreationFailureIsClear(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state-file")
	if err := os.WriteFile(statePath, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t)
	cfg.StateDir = statePath
	cfg.Admin = config.AdminConfig{
		Enabled:    true,
		Listen:     reservedTCPAddress(t, "127.0.0.1"),
		SessionTTL: time.Hour,
		LoginBurst: 5,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := Run(ctx, cfg, "test", discardLogger(), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "initialize state directory") {
		t.Fatalf("Run() = %v, want clear state directory error", err)
	}
}

func TestRunAdminDefaultsStateDirToConfigDir(t *testing.T) {
	cfg := testConfig(t)
	cfg.Admin = config.AdminConfig{
		Enabled:    true,
		Listen:     reservedTCPAddress(t, "127.0.0.1"),
		SessionTTL: time.Hour,
		LoginBurst: 5,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := Run(ctx, cfg, "test", discardLogger(), nil, nil); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.ConfigDir, "admin", "session.key")); err != nil {
		t.Fatalf("default state directory session key: %v", err)
	}
}

func TestRunWarnsWhenFirstRunAdminIsNotLoopbackOnly(t *testing.T) {
	address := reservedTCPAddress(t, "127.0.0.1")
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t)
	cfg.StateDir = t.TempDir()
	cfg.Admin = config.AdminConfig{
		Enabled:    true,
		Listen:     net.JoinHostPort("0.0.0.0", port),
		SessionTTL: time.Hour,
		LoginBurst: 5,
	}

	var logs lockedBuffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan []net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, "test", logger, nil, nil, WithReadyFunc(func(addrs []net.Addr) {
			ready <- addrs
		}))
	}()
	defer cancel()

	readyURL(t, ready, done)
	waitForLog(t, &logs, "ADMIN PLANE EXPOSED WITHOUT A PASSWORD")
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3 seconds")
	}
}

func TestLoopbackOnlyListen(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{address: "127.0.0.1:8080", want: true},
		{address: "[::1]:8080", want: true},
		{address: "localhost:8080", want: true},
		{address: "0.0.0.0:8080", want: false},
		{address: "[::]:8080", want: false},
		{address: "192.168.50.10:8080", want: false},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			if got := loopbackOnlyListen(test.address); got != test.want {
				t.Fatalf("loopbackOnlyListen(%q) = %t, want %t", test.address, got, test.want)
			}
		})
	}
}

func TestRunReloadsWithoutDroppingLastGoodConfiguration(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	writeReloadConfig(t, path, "127.0.0.1:0", "AAA", "info")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	var logs lockedBuffer
	var level slog.LevelVar
	level.Set(slog.LevelInfo)
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: &level}))
	reloadCh := make(chan string, 1)
	ready := make(chan []net.Addr, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, "test", logger, nil, reloadCh,
			WithReadyFunc(func(addrs []net.Addr) {
				ready <- addrs
			}),
			WithLogLevel(&level),
		)
	}()
	defer cancel()

	baseURL := readyURL(t, ready, done)
	client := &http.Client{Timeout: 500 * time.Millisecond}
	defer client.CloseIdleConnections()
	waitForBody(t, client, baseURL+"/rule", "AAA")

	writeReloadConfig(t, path, "127.0.0.1:0", "BBB", "debug")
	reloadCh <- path
	waitForBody(t, client, baseURL+"/rule", "BBB")
	if got := level.Level(); got != slog.LevelDebug {
		t.Fatalf("log level after reload = %s, want DEBUG", got)
	}
	waitForLog(t, &logs, `"configuration reloaded"`)
	if !strings.Contains(logs.String(), `"rule_count":1`) {
		t.Fatalf("reload log lacks rule count: %s", logs.String())
	}

	if err := os.WriteFile(path, []byte("rules: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reloadCh <- path
	waitForLog(t, &logs, "reload failed, keeping previous configuration")
	if body := getBody(t, client, baseURL+"/rule"); body != "BBB" {
		t.Fatalf("body after broken reload = %q, want BBB", body)
	}

	writeReloadConfig(t, path, "127.0.0.1:65534", "CCC", "debug")
	reloadCh <- path
	waitForBody(t, client, baseURL+"/rule", "CCC")
	waitForLog(t, &logs, "requires a restart to take effect")

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3 seconds")
	}
}

func TestRunStaticTLSHTTP2(t *testing.T) {
	certFile, keyFile, roots := makeStaticCertificate(t, "blocked.test")
	cfg := testConfig(t)
	cfg.Listen.HTTP = nil
	cfg.Listen.HTTPS = []string{"127.0.0.1:0"}
	cfg.TLS = config.TLSConfig{
		Mode: "static",
		Static: config.TLSStatic{Certs: []config.CertPair{{
			Hosts: []string{"blocked.test"}, CertFile: certFile, KeyFile: keyFile,
		}}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan []net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, "test", discardLogger(), nil, nil, WithReadyFunc(func(addrs []net.Addr) {
			ready <- addrs
		}))
	}()
	defer cancel()

	var address net.Addr
	select {
	case addrs := <-ready:
		if len(addrs) != 1 {
			t.Fatalf("ready addresses = %v, want only the HTTPS listener", addrs)
		}
		address = addrs[0]
	case err := <-done:
		t.Fatalf("Run returned before ready: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not become ready")
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    roots,
			ServerName: "blocked.test",
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	response, err := client.Get("https://" + address.String() + "/ad.js")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	client.CloseIdleConnections()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK || response.ProtoMajor != 2 {
		t.Fatalf("HTTPS response = status %d protocol %s, want 200 over HTTP/2", response.StatusCode, response.Proto)
	}
	if response.Header.Get("X-Sinkhole") != "1" || string(body) != "/* sinkhole */\n" {
		t.Fatalf("HTTPS placeholder = X-Sinkhole %q body %q", response.Header.Get("X-Sinkhole"), body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3 seconds")
	}
}

func TestRunLocalCATLS(t *testing.T) {
	directory := t.TempDir()
	certFile, keyFile, err := tlsx.CreateCA(directory, "App Local CA", 1)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to add local CA certificate to roots")
	}

	cfg := testConfig(t)
	cfg.Listen.HTTP = nil
	cfg.Listen.HTTPS = []string{"127.0.0.1:0"}
	cfg.TLS = config.TLSConfig{Mode: "local-ca", LocalCA: config.TLSLocalCA{
		CACert: certFile, CAKey: keyFile, CacheSize: 8, LeafTTL: time.Hour,
	}}

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan []net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, "test", discardLogger(), nil, nil, WithReadyFunc(func(addrs []net.Addr) {
			ready <- addrs
		}))
	}()
	defer cancel()

	var address net.Addr
	select {
	case addrs := <-ready:
		if len(addrs) != 1 {
			t.Fatalf("ready addresses = %v, want one HTTPS listener", addrs)
		}
		address = addrs[0]
	case err := <-done:
		t.Fatalf("Run returned before ready: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not become ready")
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: roots, ServerName: "x.test", MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	response, err := client.Get("https://" + address.String() + "/ad.js")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	client.CloseIdleConnections()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Sinkhole") != "1" || string(body) != "/* sinkhole */\n" {
		t.Fatalf("local-ca response = status %d X-Sinkhole %q body %q", response.StatusCode, response.Header.Get("X-Sinkhole"), body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3 seconds")
	}
}

func TestRunBootstrapsCAAndServesDefaultTLSPlanes(t *testing.T) {
	stateDir := t.TempDir()
	cfg, err := config.ParseBytes(nil, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	dataHTTP := reservedTCPAddress(t, "127.0.0.1")
	dataHTTPS := reservedTCPAddress(t, "127.0.0.1")
	adminHTTP := reservedTCPAddress(t, "127.0.0.1")
	adminHTTPS := reservedTCPAddress(t, "127.0.0.1")
	managementEnabled := false
	cfg.Listen = config.ListenConfig{HTTP: []string{dataHTTP}, HTTPS: []string{dataHTTPS}}
	cfg.Management.Enabled = &managementEnabled
	cfg.Admin.Enabled = true
	cfg.Admin.Listen = adminHTTP
	cfg.Admin.TLS.Listen = adminHTTPS

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	ready := make(chan []net.Addr, 1)
	go func() {
		done <- Run(ctx, cfg, "test", discardLogger(), nil, nil, WithReadyFunc(func(addrs []net.Addr) {
			ready <- addrs
		}), WithAdminPassword("configured secure password"))
	}()
	defer cancel()

	select {
	case addrs := <-ready:
		if len(addrs) != 2 {
			t.Fatalf("ready addresses = %v, want HTTP and HTTPS", addrs)
		}
	case err := <-done:
		t.Fatalf("Run returned before ready: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not become ready")
	}
	appState, err := state.New(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	credential, present, err := admin.LoadCredential(appState)
	if err != nil || !present || !credential.Verify("configured secure password") {
		t.Fatalf("configured admin credential = present %t, error %v", present, err)
	}

	caPath := filepath.Join(stateDir, "tls", "ca.cert.pem")
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read generated CA: %v", err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatal("generated CA is not PEM")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.IsCA || ca.Subject.CommonName != "Sinkhole Responder Local CA" {
		t.Fatalf("generated certificate = IsCA %t CN %q", ca.IsCA, ca.Subject.CommonName)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "tls", "ca.key.pem")); err != nil {
		t.Fatalf("generated CA key: %v", err)
	}

	response, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + dataHTTP + "/ad.js")
	if err != nil {
		t.Fatalf("plain HTTP data plane: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Sinkhole") != "1" {
		t.Fatalf("plain HTTP data response = %d X-Sinkhole %q", response.StatusCode, response.Header.Get("X-Sinkhole"))
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12,
	}}
	client := &http.Client{Transport: transport, Timeout: 500 * time.Millisecond}
	defer client.CloseIdleConnections()
	var adminResponse *http.Response
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		adminResponse, err = client.Get("https://" + adminHTTPS + "/setup")
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("admin HTTPS: %v", err)
	}
	adminResponse.Body.Close()
	if adminResponse.StatusCode != http.StatusOK || adminResponse.TLS == nil || len(adminResponse.TLS.PeerCertificates) == 0 {
		t.Fatalf("admin HTTPS response = status %d TLS %#v", adminResponse.StatusCode, adminResponse.TLS)
	}
	leaf := adminResponse.TLS.PeerCertificates[0]
	if validity := leaf.NotAfter.Sub(leaf.NotBefore); validity > 397*24*time.Hour {
		t.Fatalf("admin leaf validity = %v, want <= 397 days", validity)
	}
	if leaf.Issuer.String() != ca.Subject.String() {
		t.Fatalf("admin leaf issuer = %q, want %q", leaf.Issuer, ca.Subject)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestRunRejectsUnsafeLocalCAKeyPermissions(t *testing.T) {
	directory := t.TempDir()
	certFile, keyFile, err := tlsx.CreateCA(directory, "Unsafe App Local CA", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyFile, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig(t)
	cfg.Listen.HTTP = nil
	cfg.Listen.HTTPS = []string{"127.0.0.1:0"}
	cfg.TLS = config.TLSConfig{Mode: "local-ca", LocalCA: config.TLSLocalCA{
		CACert: certFile, CAKey: keyFile, CacheSize: 8, LeafTTL: time.Hour,
	}}
	err = Run(context.Background(), cfg, "test", discardLogger(), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "unsafe permissions 0644") {
		t.Fatalf("Run() = %v, want unsafe key permissions error", err)
	}
}

func TestRunRejectsConfiguredPasswordWhenAdminDisabled(t *testing.T) {
	cfg := testConfig(t)
	err := Run(context.Background(), cfg, "test", discardLogger(), nil, nil, WithAdminPassword("configured secure password"))
	if err == nil || !strings.Contains(err.Error(), "admin plane is disabled") {
		t.Fatalf("Run() = %v, want disabled-admin password error", err)
	}
}

func TestConfigValidationRequiresDataListener(t *testing.T) {
	cfg := testConfig(t)
	cfg.Listen.HTTP = nil
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "at least one listen.http or listen.https address is required") {
		t.Fatalf("Validate() = %v, want no-listener error", err)
	}
}

func TestRestartRequired(t *testing.T) {
	tests := []struct {
		name   string
		change func(*config.Config)
		want   bool
	}{
		{name: "HTTP listener", change: func(cfg *config.Config) { cfg.Listen.HTTP = []string{"127.0.0.1:1"} }, want: true},
		{name: "HTTPS listener", change: func(cfg *config.Config) { cfg.Listen.HTTPS = []string{"127.0.0.1:2"} }, want: true},
		{name: "TLS", change: func(cfg *config.Config) { cfg.TLS.Mode = "static" }, want: true},
		{name: "management", change: func(cfg *config.Config) { cfg.Management.AllowExternal = true }, want: true},
		{name: "limits", change: func(cfg *config.Config) { cfg.Limits.MaxBodyBytes++ }, want: true},
		{name: "state dir", change: func(cfg *config.Config) { cfg.StateDir = "/tmp/sinkhole-other" }, want: true},
		{name: "admin listener", change: func(cfg *config.Config) { cfg.Admin.Listen = "127.0.0.1:9" }, want: true},
		{name: "admin TLS", change: func(cfg *config.Config) { cfg.Admin.TLS.Enabled = !cfg.Admin.TLS.Enabled }, want: true},
		{name: "logging request setting is live", change: func(cfg *config.Config) { cfg.Logging.LogQuery = true }, want: false},
		{name: "logging level is live", change: func(cfg *config.Config) { cfg.Logging.Level = "debug" }, want: false},
		{name: "live defaults", change: func(cfg *config.Config) { cfg.Defaults.Status = http.StatusNoContent }, want: false},
		{name: "admin session TTL is live", change: func(cfg *config.Config) { cfg.Admin.SessionTTL += time.Minute }, want: false},
		{name: "admin login rate is live", change: func(cfg *config.Config) { cfg.Admin.LoginRatePerIP++ }, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			initial := testConfig(t)
			reloaded := testConfig(t)
			test.change(reloaded)
			if got := config.RestartRequired(initial, reloaded); got != test.want {
				t.Fatalf("RestartRequired() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestRunDoesNotLeakGoroutines(t *testing.T) {
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	before := runtime.NumGoroutine()

	cfg := testConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan []net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, "test", discardLogger(), nil, nil, WithReadyFunc(func(addrs []net.Addr) {
			ready <- addrs
		}))
	}()
	readyURL(t, ready, done)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3 seconds")
	}

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+5 {
		t.Fatalf("goroutines before=%d after=%d, want after <= %d", before, after, before+5)
	}
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	managementEnabled := false
	accessLog := false
	anonymizeClient := true
	return &config.Config{
		ConfigDir: t.TempDir(),
		Listen:    config.ListenConfig{HTTP: []string{"127.0.0.1:0"}},
		Management: config.MgmtConfig{
			Enabled: &managementEnabled,
			Listen:  "127.0.0.1:0",
		},
		TLS: config.TLSConfig{Mode: "disabled"},
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
			Level:           "info",
			AccessLog:       &accessLog,
			AnonymizeClient: &anonymizeClient,
		},
		JSONP: config.JSONPConfig{Param: "callback"},
	}
}

func readyURL(t *testing.T, ready <-chan []net.Addr, done <-chan error) string {
	t.Helper()
	select {
	case addrs := <-ready:
		if len(addrs) != 1 {
			t.Fatalf("ready addresses = %v, want one", addrs)
		}
		return "http://" + addrs[0].String()
	case err := <-done:
		t.Fatalf("Run returned before ready: %v", err)
		return ""
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not become ready")
		return ""
	}
}

func reservedTCPAddress(t *testing.T, host string) string {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func waitForHTTPStatus(t *testing.T, url string, want int) {
	t.Helper()
	client := &http.Client{Timeout: 200 * time.Millisecond}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		response, err := client.Get(url)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == want {
				return
			}
			lastErr = fmt.Errorf("status = %d, want %d", response.StatusCode, want)
		} else {
			lastErr = err
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("GET %s did not return %d: %v", url, want, lastErr)
}

func writeReloadConfig(t *testing.T, path, listen, body, level string) {
	t.Helper()
	contents := fmt.Sprintf(`listen:
  http: [%q]
  https: []
management:
  enabled: false
  listen: 127.0.0.1:9090
tls:
  mode: disabled
logging:
  level: %s
rules:
  - name: dynamic
    path_glob: /rule
    response:
      status: 200
      content_type: text/plain
      body: %q
`, listen, level, body)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitForBody(t *testing.T, client *http.Client, url, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		got = getBody(t, client, url)
		if got == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("body = %q, want %q within 2 seconds", got, want)
}

func getBody(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d", url, response.StatusCode)
	}
	return string(body)
}

func waitForLog(t *testing.T, logs *lockedBuffer, substring string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(logs.String(), substring) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("log does not contain %q: %s", substring, logs.String())
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func makeStaticCertificate(t *testing.T, hosts ...string) (string, string, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "App Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: hosts[0]},
		DNSNames:     append([]string(nil), hosts...),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCertificate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certFile := filepath.Join(directory, "leaf.pem")
	keyFile := filepath.Join(directory, "leaf-key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	return certFile, keyFile, roots
}
