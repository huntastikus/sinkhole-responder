package tlsx

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/config"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/mgmt"
)

func TestLocalCAConfigMintsVerifiedLeafAndWarns(t *testing.T) {
	ca := makeCA(t)
	certFile, keyFile, keyPEM := writeCAFiles(t, ca, 0o600)
	metrics := mgmt.NewMetrics("test")
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	leafTTL := 30 * time.Minute
	tlsConfig, err := LocalCAConfig(config.TLSLocalCA{
		CACert: certFile, CAKey: keyFile, CacheSize: 8, LeafTTL: leafTTL,
	}, metrics, logger)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.certificate)
	before := time.Now()
	leaf, negotiated, err := verifiedHandshake(t, tlsConfig, "blocked.example.test", roots)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "blocked.example.test" {
		t.Fatalf("leaf DNSNames = %v", leaf.DNSNames)
	}
	if leaf.Issuer.String() != ca.certificate.Subject.String() {
		t.Fatalf("leaf issuer = %q, want %q", leaf.Issuer, ca.certificate.Subject)
	}
	if leaf.NotAfter.After(ca.certificate.NotAfter) {
		t.Fatalf("leaf NotAfter %v exceeds CA NotAfter %v", leaf.NotAfter, ca.certificate.NotAfter)
	}
	if leaf.NotAfter.After(before.Add(leafTTL + time.Second)) {
		t.Fatalf("leaf NotAfter %v exceeds configured TTL", leaf.NotAfter)
	}
	if negotiated != "h2" {
		t.Fatalf("negotiated protocol = %q, want h2", negotiated)
	}

	fingerprintBytes := sha256.Sum256(ca.certificate.Raw)
	fingerprint := strings.ToUpper(hex.EncodeToString(fingerprintBytes[:]))
	logText := logs.String()
	if !strings.Contains(logText, "impersonate") || !strings.Contains(logText, fingerprint) {
		t.Fatalf("startup warning missing security text or fingerprint: %s", logText)
	}
	if strings.Contains(logText, "PRIVATE KEY") || strings.Contains(logText, string(keyPEM)) {
		t.Fatalf("startup log leaked CA key material: %s", logText)
	}
}

func TestLocalCAConfigCachesAndUpdatesMetric(t *testing.T) {
	ca := makeCA(t)
	certFile, keyFile, _ := writeCAFiles(t, ca, 0o600)
	metrics := mgmt.NewMetrics("test")
	tlsConfig, err := LocalCAConfig(config.TLSLocalCA{
		CACert: certFile, CAKey: keyFile, CacheSize: 4, LeafTTL: time.Hour,
	}, metrics, discardTLSLogger())
	if err != nil {
		t.Fatal(err)
	}

	first, _ := handshake(t, tlsConfig, "same.test", nil, 0)
	second, _ := handshake(t, tlsConfig, "SAME.TEST", nil, 0)
	other, _ := handshake(t, tlsConfig, "other.test", nil, 0)
	if first.SerialNumber.Cmp(second.SerialNumber) != 0 {
		t.Fatalf("same SNI serial changed: %s != %s", first.SerialNumber, second.SerialNumber)
	}
	if first.SerialNumber.Cmp(other.SerialNumber) == 0 {
		t.Fatalf("different SNI reused serial %s", first.SerialNumber)
	}
	var metric bytes.Buffer
	metrics.WritePrometheus(&metric)
	if !strings.Contains(metric.String(), "sinkhole_tls_leaf_cache_entries 2\n") {
		t.Fatalf("leaf cache metric missing or wrong: %s", metric.String())
	}
}

func TestLocalCAConfigEvictsLeastRecentlyUsed(t *testing.T) {
	ca := makeCA(t)
	certFile, keyFile, _ := writeCAFiles(t, ca, 0o600)
	tlsConfig, err := LocalCAConfig(config.TLSLocalCA{
		CACert: certFile, CAKey: keyFile, CacheSize: 2, LeafTTL: time.Hour,
	}, nil, discardTLSLogger())
	if err != nil {
		t.Fatal(err)
	}

	oldest, _ := handshake(t, tlsConfig, "oldest.test", nil, 0)
	_, _ = handshake(t, tlsConfig, "middle.test", nil, 0)
	_, _ = handshake(t, tlsConfig, "newest.test", nil, 0)
	reminted, _ := handshake(t, tlsConfig, "oldest.test", nil, 0)
	if oldest.SerialNumber.Cmp(reminted.SerialNumber) == 0 {
		t.Fatalf("evicted SNI retained serial %s", oldest.SerialNumber)
	}
}

func TestLeafMinterRegeneratesExpiredEntry(t *testing.T) {
	ca := makeCA(t)
	certFile, keyFile, _ := writeCAFiles(t, ca, 0o600)
	parsedCA, signer, err := loadLocalCA(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	minter := &leafMinter{
		entries: make(map[string]*list.Element), lru: list.New(), capacity: 2,
		leafTTL: time.Minute, ca: parsedCA, caKey: signer, now: func() time.Time { return now },
	}
	first, err := minter.certificateFor("expiry.test")
	if err != nil {
		t.Fatal(err)
	}
	now = first.Leaf.NotAfter.Add(time.Nanosecond)
	second, err := minter.certificateFor("expiry.test")
	if err != nil {
		t.Fatal(err)
	}
	if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) == 0 {
		t.Fatalf("expired leaf retained serial %s", first.Leaf.SerialNumber)
	}
	if len(minter.entries) > minter.capacity {
		t.Fatalf("cache length = %d, capacity = %d", len(minter.entries), minter.capacity)
	}
}

func TestLeafMinterRefreshesEntryWithinOneMinuteOfExpiry(t *testing.T) {
	ca := makeCA(t)
	certFile, keyFile, _ := writeCAFiles(t, ca, 0o600)
	parsedCA, signer, err := loadLocalCA(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	minter := &leafMinter{
		entries: make(map[string]*list.Element), lru: list.New(), capacity: 2,
		leafTTL: 2 * time.Minute, ca: parsedCA, caKey: signer, now: func() time.Time { return now },
	}
	first, err := minter.certificateFor("refresh.test")
	if err != nil {
		t.Fatal(err)
	}
	now = first.Leaf.NotAfter.Add(-30 * time.Second)
	second, err := minter.certificateFor("refresh.test")
	if err != nil {
		t.Fatal(err)
	}
	if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) == 0 {
		t.Fatalf("near-expiry leaf retained serial %s", first.Leaf.SerialNumber)
	}
}

func TestLocalCAConfigKeyPermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o600, 0o400} {
		t.Run(mode.String(), func(t *testing.T) {
			ca := makeCA(t)
			certFile, keyFile, _ := writeCAFiles(t, ca, mode)
			_, err := LocalCAConfig(config.TLSLocalCA{
				CACert: certFile, CAKey: keyFile, CacheSize: 2, LeafTTL: time.Minute,
			}, nil, discardTLSLogger())
			unsafe := mode&0o077 != 0
			if unsafe && (err == nil || !strings.Contains(err.Error(), "unsafe permissions")) {
				t.Fatalf("mode %04o error = %v, want unsafe permissions", mode, err)
			}
			if !unsafe && err != nil {
				t.Fatalf("mode %04o error = %v", mode, err)
			}
		})
	}
}

func TestLocalCAConfigRejectsInvalidCAAndMismatch(t *testing.T) {
	ca := makeCA(t)
	leafCert, leafKey := makeLeaf(t, ca, "not-ca.test")
	_, err := LocalCAConfig(config.TLSLocalCA{
		CACert: leafCert, CAKey: leafKey, CacheSize: 2, LeafTTL: time.Minute,
	}, nil, discardTLSLogger())
	if err == nil || !strings.Contains(err.Error(), "not a CA") {
		t.Fatalf("non-CA error = %v, want not a CA", err)
	}

	otherCA := makeCA(t)
	_, otherKey, _ := writeCAFiles(t, otherCA, 0o600)
	_, err = LocalCAConfig(config.TLSLocalCA{
		CACert: ca.certFile, CAKey: otherKey, CacheSize: 2, LeafTTL: time.Minute,
	}, nil, discardTLSLogger())
	if err == nil || !strings.Contains(err.Error(), "private key does not match public key") {
		t.Fatalf("mismatch error = %v", err)
	}
}

func TestLocalCAConfigRejectsMissingOrNonHostnameSNI(t *testing.T) {
	ca := makeCA(t)
	certFile, keyFile, _ := writeCAFiles(t, ca, 0o600)
	tlsConfig, err := LocalCAConfig(config.TLSLocalCA{
		CACert: certFile, CAKey: keyFile, CacheSize: 2, LeafTTL: time.Minute,
	}, nil, discardTLSLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := handshakeError(t, tlsConfig, "", 0); err == nil {
		t.Fatal("handshake without SNI succeeded")
	}
	if err := handshakeError(t, tlsConfig, "127.0.0.1", 0); err == nil {
		t.Fatal("handshake with IP-literal ServerName succeeded")
	}
	if _, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "bad_host.test"}); err == nil {
		t.Fatal("invalid hostname was accepted")
	}
}

func writeCAFiles(t *testing.T, ca testCA, mode os.FileMode) (string, string, []byte) {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	directory := t.TempDir()
	certFile := filepath.Join(directory, "ca.pem")
	keyFile := filepath.Join(directory, "ca-key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyFile, mode); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, keyPEM
}

func verifiedHandshake(t *testing.T, serverConfig *tls.Config, serverName string, roots *x509.CertPool) (*x509.Certificate, string, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		connection, err := tls.NewListener(listener, serverConfig).Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		serverDone <- connection.(*tls.Conn).Handshake()
	}()
	connection, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		ServerName: serverName, RootCAs: roots, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		<-serverDone
		return nil, "", err
	}
	state := connection.ConnectionState()
	connection.Close()
	if err := <-serverDone; err != nil {
		return nil, "", err
	}
	return state.PeerCertificates[0], state.NegotiatedProtocol, nil
}

func discardTLSLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
