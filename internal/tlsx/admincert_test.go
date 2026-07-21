package tlsx

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/config"
)

func TestResolveCAPaths(t *testing.T) {
	stateDir := t.TempDir()
	certPath, keyPath := ResolveCAPaths(config.TLSLocalCA{}, stateDir)
	if want := filepath.Join(stateDir, "tls", "ca.cert.pem"); certPath != want {
		t.Fatalf("default cert path = %q, want %q", certPath, want)
	}
	if want := filepath.Join(stateDir, "tls", "ca.key.pem"); keyPath != want {
		t.Fatalf("default key path = %q, want %q", keyPath, want)
	}

	certPath, keyPath = ResolveCAPaths(config.TLSLocalCA{CACert: "configured.pem", CAKey: "configured-key.pem"}, stateDir)
	if certPath != "configured.pem" || keyPath != "configured-key.pem" {
		t.Fatalf("configured paths = %q, %q", certPath, keyPath)
	}
}

func TestAdminCAConfigMintsVerifiedDNSLeaf(t *testing.T) {
	now := time.Now()
	ca, certPath, keyPath := createAdminTestCA(t)
	tlsConfig, err := newAdminCAConfig(certPath, keyPath, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "Admin.Example.TEST"})
	if err != nil {
		t.Fatal(err)
	}
	leaf := certificate.Leaf
	if !slices.Contains(leaf.DNSNames, "admin.example.test") || !slices.Contains(leaf.DNSNames, "localhost") {
		t.Fatalf("DNS SANs = %v", leaf.DNSNames)
	}
	assertAdminLoopbackSANs(t, leaf)
	if validity := leaf.NotAfter.Sub(leaf.NotBefore); validity > adminLeafLifetime {
		t.Fatalf("leaf validity = %v, want <= %v", validity, adminLeafLifetime)
	}
	verifyAdminLeaf(t, leaf, ca, "admin.example.test", now)
	if tlsConfig.MinVersion != tls.VersionTLS12 || !slices.Equal(tlsConfig.NextProtos, []string{"h2", "http/1.1"}) {
		t.Fatalf("TLS settings = min %d protocols %v", tlsConfig.MinVersion, tlsConfig.NextProtos)
	}
}

func TestAdminCAConfigUsesConnectionLocalIPWithoutSNI(t *testing.T) {
	now := time.Now()
	ca, certPath, keyPath := createAdminTestCA(t)
	tlsConfig, err := newAdminCAConfig(certPath, keyPath, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	hello := &tls.ClientHelloInfo{Conn: localAddressConn{
		Conn: server,
		addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.44"), Port: 8443},
	}}
	certificate, err := tlsConfig.GetCertificate(hello)
	if err != nil {
		t.Fatal(err)
	}
	leaf := certificate.Leaf
	if !containsIP(leaf.IPAddresses, net.ParseIP("192.0.2.44")) {
		t.Fatalf("IP SANs = %v, want connection local IP", leaf.IPAddresses)
	}
	assertAdminLoopbackSANs(t, leaf)
	verifyAdminLeaf(t, leaf, ca, "192.0.2.44", now)
}

func TestAdminCAConfigRemintsNearExpiry(t *testing.T) {
	now := time.Now()
	_, certPath, keyPath := createAdminTestCA(t)
	tlsConfig, err := newAdminCAConfig(certPath, keyPath, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	hello := &tls.ClientHelloInfo{ServerName: "renew.example.test"}
	first, err := tlsConfig.GetCertificate(hello)
	if err != nil {
		t.Fatal(err)
	}
	now = first.Leaf.NotAfter.Add(-first.Leaf.NotAfter.Sub(first.Leaf.NotBefore) / 20)
	second, err := tlsConfig.GetCertificate(hello)
	if err != nil {
		t.Fatal(err)
	}
	if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) == 0 {
		t.Fatalf("near-expiry leaf retained serial %s", first.Leaf.SerialNumber)
	}
}

func TestAdminCAConfigRemintsAfterExpiry(t *testing.T) {
	now := time.Now()
	_, certPath, keyPath := createAdminTestCA(t)
	tlsConfig, err := newAdminCAConfig(certPath, keyPath, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	hello := &tls.ClientHelloInfo{ServerName: "expired.example.test"}
	first, err := tlsConfig.GetCertificate(hello)
	if err != nil {
		t.Fatal(err)
	}
	now = first.Leaf.NotAfter.Add(time.Second)
	second, err := tlsConfig.GetCertificate(hello)
	if err != nil {
		t.Fatal(err)
	}
	if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) == 0 {
		t.Fatalf("expired leaf retained serial %s", first.Leaf.SerialNumber)
	}
}

type localAddressConn struct {
	net.Conn
	addr net.Addr
}

func (c localAddressConn) LocalAddr() net.Addr { return c.addr }

func createAdminTestCA(t *testing.T) (*x509.Certificate, string, string) {
	t.Helper()
	certPath, keyPath, err := CreateCA(filepath.Join(t.TempDir(), "tls"), "Admin Test CA", 10)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		t.Fatal("CA certificate is not PEM")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return ca, certPath, keyPath
}

func verifyAdminLeaf(t *testing.T, leaf, ca *x509.Certificate, dnsName string, now time.Time) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		DNSName:     dnsName,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("verify CA-signed admin leaf: %v", err)
	}
}

func assertAdminLoopbackSANs(t *testing.T, leaf *x509.Certificate) {
	t.Helper()
	if !slices.Contains(leaf.DNSNames, "localhost") ||
		!containsIP(leaf.IPAddresses, net.ParseIP("127.0.0.1")) ||
		!containsIP(leaf.IPAddresses, net.ParseIP("::1")) {
		t.Fatalf("loopback SANs missing: DNS %v IP %v", leaf.DNSNames, leaf.IPAddresses)
	}
}

func containsIP(addresses []net.IP, want net.IP) bool {
	for _, address := range addresses {
		if address.Equal(want) {
			return true
		}
	}
	return false
}
