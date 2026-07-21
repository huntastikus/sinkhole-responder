package tlsx

import (
	"container/list"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	adminLeafCacheSize = 128
	adminLeafLifetime  = 397 * 24 * time.Hour
)

type cachedAdminLeaf struct {
	key         string
	certificate *tls.Certificate
	notBefore   time.Time
	notAfter    time.Time
}

type adminLeafMinter struct {
	mu       sync.Mutex
	entries  map[string]*list.Element
	lru      *list.List
	capacity int
	ca       *x509.Certificate
	caKey    crypto.Signer
	now      func() time.Time
}

// AdminCAConfig returns a *tls.Config whose GetCertificate mints short-lived
// CA-signed leaves on demand for the host the client actually used.
func AdminCAConfig(caCertPath, caKeyPath string) (*tls.Config, error) {
	return newAdminCAConfig(caCertPath, caKeyPath, time.Now)
}

func newAdminCAConfig(caCertPath, caKeyPath string, now func() time.Time) (*tls.Config, error) {
	ca, caKey, err := loadLocalCA(caCertPath, caKeyPath)
	if err != nil {
		return nil, err
	}
	minter := &adminLeafMinter{
		entries:  make(map[string]*list.Element),
		lru:      list.New(),
		capacity: adminLeafCacheSize,
		ca:       ca,
		caKey:    caKey,
		now:      now,
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			target, isIP, err := adminCertificateTarget(hello)
			if err != nil {
				return nil, err
			}
			return minter.certificateFor(target, isIP)
		},
	}, nil
}

func adminCertificateTarget(hello *tls.ClientHelloInfo) (string, bool, error) {
	if hello == nil {
		return "", false, fmt.Errorf("admin TLS client hello is nil")
	}
	serverName, err := normalizeServerName(hello.ServerName)
	if err == nil && serverName != "" && net.ParseIP(serverName) == nil && validDNSHostname(serverName) {
		return serverName, false, nil
	}
	if hello.Conn == nil || hello.Conn.LocalAddr() == nil {
		return "", false, fmt.Errorf("admin TLS connection local address is unavailable")
	}
	localIP, err := addressIP(hello.Conn.LocalAddr())
	if err != nil {
		return "", false, err
	}
	return localIP.String(), true, nil
}

func addressIP(address net.Addr) (net.IP, error) {
	if tcpAddress, ok := address.(*net.TCPAddr); ok && tcpAddress.IP != nil {
		return tcpAddress.IP, nil
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return nil, fmt.Errorf("parse admin TLS connection local address %q: %w", address, err)
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return nil, fmt.Errorf("admin TLS connection local address %q has no IP", address)
	}
	return ip, nil
}

func (m *adminLeafMinter) certificateFor(target string, isIP bool) (*tls.Certificate, error) {
	key := "dns:" + target
	if isIP {
		key = "ip:" + target
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	if element, ok := m.entries[key]; ok {
		entry := element.Value.(*cachedAdminLeaf)
		refreshWindow := entry.notAfter.Sub(entry.notBefore) / 10
		if now.Add(refreshWindow).Before(entry.notAfter) {
			m.lru.MoveToFront(element)
			return entry.certificate, nil
		}
		m.remove(element)
	}

	certificate, err := m.mint(target, isIP, now)
	if err != nil {
		return nil, err
	}
	entry := &cachedAdminLeaf{
		key:         key,
		certificate: certificate,
		notBefore:   certificate.Leaf.NotBefore,
		notAfter:    certificate.Leaf.NotAfter,
	}
	element := m.lru.PushFront(entry)
	m.entries[key] = element
	if len(m.entries) > m.capacity {
		m.remove(m.lru.Back())
	}
	return certificate, nil
}

func (m *adminLeafMinter) remove(element *list.Element) {
	entry := element.Value.(*cachedAdminLeaf)
	delete(m.entries, entry.key)
	m.lru.Remove(element)
}

func (m *adminLeafMinter) mint(target string, isIP bool, now time.Time) (*tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate admin leaf key for %s: %w", target, err)
	}
	serial, err := randomCertificateSerial()
	if err != nil {
		return nil, fmt.Errorf("generate admin leaf serial for %s: %w", target, err)
	}
	notBefore := now.Add(-5 * time.Minute)
	notAfter := notBefore.Add(adminLeafLifetime)
	if m.ca.NotAfter.Before(notAfter) {
		notAfter = m.ca.NotAfter
	}
	if !notAfter.After(notBefore) {
		return nil, fmt.Errorf("local CA expires too soon to mint an admin leaf for %s", target)
	}

	dnsNames := []string{"localhost"}
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	commonName := target
	if isIP {
		targetIP := net.ParseIP(target)
		if targetIP == nil {
			return nil, fmt.Errorf("invalid admin leaf IP %q", target)
		}
		ipAddresses = appendUniqueIP(ipAddresses, targetIP)
	} else if target != "localhost" {
		dnsNames = append(dnsNames, target)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, m.ca, &privateKey.PublicKey, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("sign admin leaf certificate for %s: %w", target, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse minted admin leaf certificate for %s: %w", target, err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
		Leaf:        leaf,
	}, nil
}

func appendUniqueIP(addresses []net.IP, candidate net.IP) []net.IP {
	for _, address := range addresses {
		if address.Equal(candidate) {
			return addresses
		}
	}
	return append(addresses, candidate)
}
