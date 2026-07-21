package tlsx

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCreateCACreatesSecureMatchingFiles(t *testing.T) {
	directory := t.TempDir() + "/new-ca"
	before := time.Now()
	certPath, keyPath, err := CreateCA(directory, "Sinkhole Lab CA", 3)
	if err != nil {
		t.Fatal(err)
	}
	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if certInfo.Mode().Perm() != 0o644 {
		t.Fatalf("certificate mode = %04o, want 0644", certInfo.Mode().Perm())
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %04o, want 0600", keyInfo.Mode().Perm())
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		t.Fatal("certificate file does not contain PEM")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !certificate.BasicConstraintsValid || !certificate.IsCA {
		t.Fatal("created certificate is not a CA")
	}
	if certificate.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Fatalf("CA key usage = %v", certificate.KeyUsage)
	}
	wantNotAfter := before.AddDate(3, 0, 0)
	if delta := certificate.NotAfter.Sub(wantNotAfter); delta < -time.Second || delta > time.Second {
		t.Fatalf("CA NotAfter = %v, want about %v", certificate.NotAfter, wantNotAfter)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("key file does not contain PEM")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve.Params().Name != "P-384" {
		t.Fatalf("CA key = %T on unexpected curve", parsedKey)
	}
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicKey.Equal(&privateKey.PublicKey) {
		t.Fatal("CA key does not match certificate public key")
	}
}

func TestCreateCARefusesToClobberExistingFiles(t *testing.T) {
	directory := t.TempDir()
	certPath, keyPath, err := CreateCA(directory, "Original CA", 1)
	if err != nil {
		t.Fatal(err)
	}
	certBefore, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = CreateCA(directory, "Replacement CA", 2)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("second CreateCA() error = %v", err)
	}
	certAfter, _ := os.ReadFile(certPath)
	keyAfter, _ := os.ReadFile(keyPath)
	if string(certBefore) != string(certAfter) || string(keyBefore) != string(keyAfter) {
		t.Fatal("second CreateCA changed original files")
	}
}

func TestCreateCATenYearLifetime(t *testing.T) {
	before := time.Now()
	certPath, _, err := CreateCA(t.TempDir(), "Sinkhole Responder Local CA", 10)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		t.Fatal("certificate file does not contain PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	want := before.AddDate(10, 0, 0)
	if delta := certificate.NotAfter.Sub(want); delta < -time.Second || delta > time.Second {
		t.Fatalf("CA NotAfter = %v, want about %v", certificate.NotAfter, want)
	}
}
