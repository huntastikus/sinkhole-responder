package tlsx

import (
	"container/list"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/config"
	"github.com/huntastikus/sinkhole-responder/internal/mgmt"
)

type cachedLeaf struct {
	serverName  string
	certificate *tls.Certificate
	notAfter    time.Time
}

type leafMinter struct {
	mu       sync.Mutex
	entries  map[string]*list.Element
	lru      *list.List
	capacity int
	leafTTL  time.Duration
	ca       *x509.Certificate
	caKey    crypto.Signer
	metrics  *mgmt.Metrics
	now      func() time.Time
}

// LocalCAConfig builds a *tls.Config from pre-validated local CA settings and
// mints per-SNI leaf certs signed by the local CA.
func LocalCAConfig(cfg config.TLSLocalCA, metrics *mgmt.Metrics, logger *slog.Logger) (*tls.Config, error) {
	ca, caKey, err := loadLocalCA(cfg.CACert, cfg.CAKey)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	fingerprintBytes := sha256.Sum256(ca.Raw)
	fingerprint := strings.ToUpper(hex.EncodeToString(fingerprintBytes[:]))
	logger.Warn(fmt.Sprintf(`WARNING: local-ca TLS mode is ACTIVE.
This CA can impersonate ANY site to clients that trust it.
Never install this CA system-wide. Use it only in an isolated lab/home client profile.
Keep the CA private key secret.
CA subject: %s
CA SHA-256 fingerprint: %s`, ca.Subject.String(), fingerprint))

	minter := &leafMinter{
		entries:  make(map[string]*list.Element),
		lru:      list.New(),
		capacity: cfg.CacheSize,
		leafTTL:  cfg.LeafTTL,
		ca:       ca,
		caKey:    caKey,
		metrics:  metrics,
		now:      time.Now,
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
	tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		serverName, err := normalizeMintServerName(hello.ServerName)
		if err != nil {
			return nil, err
		}
		return minter.certificateFor(serverName)
	}
	return tlsConfig, nil
}

func loadLocalCA(certPath, keyPath string) (*x509.Certificate, crypto.Signer, error) {
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("stat CA key file %s: %w", keyPath, err)
	}
	if !keyInfo.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("CA key file %s is not a regular file", keyPath)
	}
	permissions := keyInfo.Mode().Perm()
	if permissions&0o077 != 0 {
		return nil, nil, fmt.Errorf("CA key file %s has unsafe permissions %04o; require 0600 or 0400", keyPath, permissions)
	}

	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load local CA certificate and key: %w", err)
	}
	ca, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("parse local CA certificate: %w", err)
	}
	if !ca.BasicConstraintsValid || !ca.IsCA {
		return nil, nil, fmt.Errorf("local CA certificate is not a CA")
	}
	caKey, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("local CA private key cannot sign certificates")
	}
	return ca, caKey, nil
}

func normalizeMintServerName(raw string) (string, error) {
	serverName, err := normalizeServerName(raw)
	if err != nil {
		return "", fmt.Errorf("normalize SNI %q: %w", raw, err)
	}
	if serverName == "" {
		return "", fmt.Errorf("local-ca TLS requires a non-empty SNI hostname")
	}
	if net.ParseIP(serverName) != nil {
		return "", fmt.Errorf("local-ca TLS refuses IP-literal SNI %q; a DNS hostname is required", raw)
	}
	if !validDNSHostname(serverName) {
		return "", fmt.Errorf("invalid SNI hostname %q after normalization", raw)
	}
	return serverName, nil
}

func validDNSHostname(host string) bool {
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || !asciiLetterOrDigit(label[0]) || !asciiLetterOrDigit(label[len(label)-1]) {
			return false
		}
		for i := 1; i < len(label)-1; i++ {
			if !asciiLetterOrDigit(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

func asciiLetterOrDigit(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= '0' && char <= '9'
}

func (m *leafMinter) certificateFor(serverName string) (*tls.Certificate, error) {
	// ponytail: single mint lock; shard if handshake throughput ever matters
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	if element, ok := m.entries[serverName]; ok {
		entry := element.Value.(*cachedLeaf)
		if now.Add(time.Minute).Before(entry.notAfter) {
			m.lru.MoveToFront(element)
			return entry.certificate, nil
		}
		m.remove(element)
	}

	certificate, err := m.mint(serverName, now)
	if err != nil {
		return nil, err
	}
	entry := &cachedLeaf{serverName: serverName, certificate: certificate, notAfter: certificate.Leaf.NotAfter}
	element := m.lru.PushFront(entry)
	m.entries[serverName] = element
	if len(m.entries) > m.capacity {
		m.remove(m.lru.Back())
	}
	m.metrics.SetLeafCacheSize(len(m.entries))
	return certificate, nil
}

func (m *leafMinter) remove(element *list.Element) {
	entry := element.Value.(*cachedLeaf)
	delete(m.entries, entry.serverName)
	m.lru.Remove(element)
	m.metrics.SetLeafCacheSize(len(m.entries))
}

func (m *leafMinter) mint(serverName string, now time.Time) (*tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key for %s: %w", serverName, err)
	}
	serial, err := randomCertificateSerial()
	if err != nil {
		return nil, fmt.Errorf("generate leaf serial for %s: %w", serverName, err)
	}
	notAfter := now.Add(m.leafTTL)
	if m.ca.NotAfter.Before(notAfter) {
		notAfter = m.ca.NotAfter
	}
	notBefore := now.Add(-5 * time.Minute)
	if !notAfter.After(notBefore) {
		return nil, fmt.Errorf("local CA expires too soon to mint a leaf for %s", serverName)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, m.ca, &privateKey.PublicKey, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("sign leaf certificate for %s: %w", serverName, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse minted leaf certificate for %s: %w", serverName, err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
		Leaf:        leaf,
	}, nil
}

func randomCertificateSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		serial, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}
		if serial.Sign() > 0 {
			return serial, nil
		}
	}
}
