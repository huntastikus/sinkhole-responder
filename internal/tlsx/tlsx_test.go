package tlsx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/config"
)

type testCA struct {
	certificate *x509.Certificate
	privateKey  *ecdsa.PrivateKey
	certFile    string
}

// makeCA creates a reusable test CA. It intentionally lives in a shared test
// file so the local-CA tests can use the same certificate fixtures in T9.
func makeCA(t *testing.T) testCA {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "Sinkhole Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certFile := filepath.Join(directory, "ca.pem")
	writePEM(t, certFile, "CERTIFICATE", der)
	return testCA{certificate: certificate, privateKey: privateKey, certFile: certFile}
}

// makeLeaf creates a CA-signed leaf and returns its PEM certificate and key
// paths. Each call uses a separate t.TempDir so files can be freely mixed in
// mismatch tests.
func makeLeaf(t *testing.T, ca testCA, hosts ...string) (string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	commonName := "test.invalid"
	if len(hosts) != 0 {
		commonName = hosts[0]
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     append([]string(nil), hosts...),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &privateKey.PublicKey, ca.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certFile := filepath.Join(directory, "leaf.pem")
	keyFile := filepath.Join(directory, "leaf-key.pem")
	writePEM(t, certFile, "CERTIFICATE", der)
	writePEM(t, keyFile, "PRIVATE KEY", keyDER)
	return certFile, keyFile
}

func TestStaticConfigSelectsCertificates(t *testing.T) {
	ca := makeCA(t)
	aCert, aKey := makeLeaf(t, ca, "a.test")
	bCert, bKey := makeLeaf(t, ca, "*.b.test")
	tlsConfig, err := StaticConfig(config.TLSStatic{Certs: []config.CertPair{
		{Hosts: []string{"a.test"}, CertFile: aCert, KeyFile: aKey},
		{Hosts: []string{"*.b.test"}, CertFile: bCert, KeyFile: bKey},
	}})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		serverName string
		wantSAN    string
	}{
		{name: "exact", serverName: "a.test", wantSAN: "a.test"},
		{name: "wildcard one label", serverName: "foo.b.test", wantSAN: "*.b.test"},
		{name: "wildcard does not cover multiple labels", serverName: "a.b.b.test", wantSAN: "a.test"},
		{name: "no SNI", wantSAN: "a.test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leaf, _ := handshake(t, tlsConfig, tt.serverName, []string{"http/1.1"}, 0)
			if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != tt.wantSAN {
				t.Fatalf("served DNS SANs = %v, want [%s]", leaf.DNSNames, tt.wantSAN)
			}
		})
	}
}

func TestStaticConfigDerivesHostsFromSANs(t *testing.T) {
	ca := makeCA(t)
	defaultCert, defaultKey := makeLeaf(t, ca, "default.test")
	derivedCert, derivedKey := makeLeaf(t, ca, "c.test")
	tlsConfig, err := StaticConfig(config.TLSStatic{Certs: []config.CertPair{
		{Hosts: []string{"default.test"}, CertFile: defaultCert, KeyFile: defaultKey},
		{CertFile: derivedCert, KeyFile: derivedKey},
	}})
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := handshake(t, tlsConfig, "c.test", nil, 0)
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "c.test" {
		t.Fatalf("served DNS SANs = %v, want [c.test]", leaf.DNSNames)
	}
}

func TestStaticConfigFallsBackToLeafSANs(t *testing.T) {
	ca := makeCA(t)
	defaultCert, defaultKey := makeLeaf(t, ca, "default.test")
	sanCert, sanKey := makeLeaf(t, ca, "san.test")
	tlsConfig, err := StaticConfig(config.TLSStatic{Certs: []config.CertPair{
		{Hosts: []string{"default.test"}, CertFile: defaultCert, KeyFile: defaultKey},
		{Hosts: []string{"alias.test"}, CertFile: sanCert, KeyFile: sanKey},
	}})
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := handshake(t, tlsConfig, "san.test", nil, 0)
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "san.test" {
		t.Fatalf("SAN fallback served DNS SANs = %v, want [san.test]", leaf.DNSNames)
	}
}

func TestStaticConfigMatchPrecedence(t *testing.T) {
	ca := makeCA(t)
	sanCert, sanKey := makeLeaf(t, ca, "target.test", "foo.b.test")
	exactCert, exactKey := makeLeaf(t, ca, "exact-choice.test")
	wildcardCert, wildcardKey := makeLeaf(t, ca, "*.b.test")
	tlsConfig, err := StaticConfig(config.TLSStatic{Certs: []config.CertPair{
		{Hosts: []string{"default.test"}, CertFile: sanCert, KeyFile: sanKey},
		{Hosts: []string{"target.test"}, CertFile: exactCert, KeyFile: exactKey},
		{Hosts: []string{"*.b.test"}, CertFile: wildcardCert, KeyFile: wildcardKey},
	}})
	if err != nil {
		t.Fatal(err)
	}

	leaf, _ := handshake(t, tlsConfig, "target.test", nil, 0)
	if leaf.Subject.CommonName != "exact-choice.test" {
		t.Fatalf("exact mapping served CN %q", leaf.Subject.CommonName)
	}
	leaf, _ = handshake(t, tlsConfig, "foo.b.test", nil, 0)
	if leaf.Subject.CommonName != "*.b.test" {
		t.Fatalf("wildcard mapping served CN %q", leaf.Subject.CommonName)
	}
}

func TestStaticConfigNormalizesCaseAndIDNA(t *testing.T) {
	ca := makeCA(t)
	aCert, aKey := makeLeaf(t, ca, "a.test")
	idnaCert, idnaKey := makeLeaf(t, ca, "xn--bcher-kva.test")
	tlsConfig, err := StaticConfig(config.TLSStatic{Certs: []config.CertPair{
		{Hosts: []string{"a.test"}, CertFile: aCert, KeyFile: aKey},
		{Hosts: []string{"bücher.test"}, CertFile: idnaCert, KeyFile: idnaKey},
	}})
	if err != nil {
		t.Fatal(err)
	}

	leaf, _ := handshake(t, tlsConfig, "A.TEST", nil, 0)
	if leaf.DNSNames[0] != "a.test" {
		t.Fatalf("case-insensitive match served %v", leaf.DNSNames)
	}
	leaf, _ = handshake(t, tlsConfig, "xn--bcher-kva.test", nil, 0)
	if leaf.DNSNames[0] != "xn--bcher-kva.test" {
		t.Fatalf("IDNA match served %v", leaf.DNSNames)
	}
}

func TestStaticConfigRejectsInvalidPairs(t *testing.T) {
	ca := makeCA(t)
	firstCert, firstKey := makeLeaf(t, ca, "first.test")
	secondCert, secondKey := makeLeaf(t, ca, "second.test")

	tests := []struct {
		name    string
		config  config.TLSStatic
		wantErr string
	}{
		{
			name: "duplicate host",
			config: config.TLSStatic{Certs: []config.CertPair{
				{Hosts: []string{"DUP.test"}, CertFile: firstCert, KeyFile: firstKey},
				{Hosts: []string{"dup.test"}, CertFile: secondCert, KeyFile: secondKey},
			}},
			wantErr: "duplicate static TLS host",
		},
		{
			name: "bad certificate path",
			config: config.TLSStatic{Certs: []config.CertPair{
				{Hosts: []string{"first.test"}, CertFile: filepath.Join(t.TempDir(), "missing.pem"), KeyFile: firstKey},
			}},
			wantErr: "load static TLS certificate pair",
		},
		{
			name: "key certificate mismatch",
			config: config.TLSStatic{Certs: []config.CertPair{
				{Hosts: []string{"first.test"}, CertFile: firstCert, KeyFile: secondKey},
			}},
			wantErr: "private key does not match public key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := StaticConfig(tt.config)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("StaticConfig() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}

}

func TestStaticConfigTLSVersionsAndALPN(t *testing.T) {
	ca := makeCA(t)
	certFile, keyFile := makeLeaf(t, ca, "a.test")
	tlsConfig, err := StaticConfig(config.TLSStatic{Certs: []config.CertPair{{
		Hosts: []string{"a.test"}, CertFile: certFile, KeyFile: keyFile,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x, want TLS 1.2", tlsConfig.MinVersion)
	}

	_, negotiated := handshake(t, tlsConfig, "a.test", []string{"h2", "http/1.1"}, 0)
	if negotiated != "h2" {
		t.Fatalf("negotiated protocol = %q, want h2", negotiated)
	}

	if err := handshakeError(t, tlsConfig, "a.test", tls.VersionTLS11); err == nil {
		t.Fatal("TLS 1.1 handshake succeeded, want failure")
	}
}

func handshake(t *testing.T, serverConfig *tls.Config, serverName string, nextProtos []string, maxVersion uint16) (*x509.Certificate, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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

	clientConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // Certificate selection is asserted directly below.
		NextProtos:         nextProtos,
		MaxVersion:         maxVersion,
	}
	connection, err := tls.Dial("tcp", listener.Addr().String(), clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	state := connection.ConnectionState()
	connection.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if len(state.PeerCertificates) == 0 {
		t.Fatal("handshake returned no peer certificate")
	}
	return state.PeerCertificates[0], state.NegotiatedProtocol
}

func handshakeError(t *testing.T, serverConfig *tls.Config, serverName string, maxVersion uint16) error {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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
	connection, clientErr := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MaxVersion:         maxVersion,
	})
	if connection != nil {
		connection.Close()
	}
	<-serverDone
	return clientErr
}

func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	return serial
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(file, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
