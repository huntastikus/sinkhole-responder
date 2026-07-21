package tlsx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CreateCA writes a new local CA cert+key to dir. Refuses to overwrite existing files.
func CreateCA(dir, commonName string, years int) (certPath, keyPath string, err error) {
	if dir == "" {
		return "", "", fmt.Errorf("CA directory must not be empty")
	}
	if commonName == "" {
		return "", "", fmt.Errorf("CA common name must not be empty")
	}
	if years < 1 {
		return "", "", fmt.Errorf("CA lifetime must be at least 1 year")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("create CA directory: %w", err)
	}

	certPath = filepath.Join(dir, "ca.cert.pem")
	keyPath = filepath.Join(dir, "ca.key.pem")
	for _, path := range []string{certPath, keyPath} {
		if _, statErr := os.Lstat(path); statErr == nil {
			return "", "", fmt.Errorf("refusing to overwrite existing CA file %s", path)
		} else if !os.IsNotExist(statErr) {
			return "", "", fmt.Errorf("check CA file %s: %w", path, statErr)
		}
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate CA private key: %w", err)
	}
	serial, err := randomCertificateSerial()
	if err != nil {
		return "", "", fmt.Errorf("generate CA serial: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(years, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", fmt.Errorf("create CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("marshal CA private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := writeExclusiveFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("write CA private key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := writeExclusiveFile(certPath, certPEM, 0o644); err != nil {
		_ = os.Remove(keyPath)
		return "", "", fmt.Errorf("write CA certificate: %w", err)
	}
	return certPath, keyPath, nil
}

func writeExclusiveFile(path string, contents []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(contents); err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}
