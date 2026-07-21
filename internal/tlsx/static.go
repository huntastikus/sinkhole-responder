// Package tlsx builds TLS configurations for public listeners.
package tlsx

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/huntastikus/sinkhole-responder/internal/config"
	"golang.org/x/net/idna"
)

// StaticConfig loads static certificate pairs and builds an SNI-aware TLS
// configuration. The first configured certificate is the deterministic
// default when the client sends no SNI or no certificate matches. When a pair
// has no explicit Hosts, its DNS subject alternative names are used instead.
func StaticConfig(sc config.TLSStatic) (*tls.Config, error) {
	if len(sc.Certs) == 0 {
		return nil, fmt.Errorf("static TLS requires at least one certificate pair")
	}

	certificates := make([]tls.Certificate, 0, len(sc.Certs))
	exact := make(map[string]int)
	wildcards := make(map[string]int)

	for i, pair := range sc.Certs {
		certificate, err := tls.LoadX509KeyPair(pair.CertFile, pair.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load static TLS certificate pair %d: %w", i, err)
		}
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse static TLS leaf certificate %d: %w", i, err)
		}
		certificate.Leaf = leaf
		certificates = append(certificates, certificate)

		hosts := pair.Hosts
		if len(hosts) == 0 {
			hosts = leaf.DNSNames
		}
		for _, configuredHost := range hosts {
			host, wildcard, err := normalizeConfiguredHost(configuredHost)
			if err != nil {
				return nil, fmt.Errorf("normalize static TLS host %q for certificate pair %d: %w", configuredHost, i, err)
			}
			hostMap := exact
			if wildcard {
				hostMap = wildcards
			}
			if previous, exists := hostMap[host]; exists && previous != i {
				return nil, fmt.Errorf("duplicate static TLS host %q in certificate pairs %d and %d", configuredHost, previous, i)
			}
			hostMap[host] = i
		}
	}

	tlsConfig := &tls.Config{
		Certificates: certificates,
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		serverName, err := normalizeServerName(hello.ServerName)
		if err == nil && serverName != "" {
			if index, ok := exact[serverName]; ok {
				return &tlsConfig.Certificates[index], nil
			}
			if firstDot := strings.IndexByte(serverName, '.'); firstDot > 0 {
				if index, ok := wildcards[serverName[firstDot+1:]]; ok {
					return &tlsConfig.Certificates[index], nil
				}
			}
			for i := range tlsConfig.Certificates {
				if tlsConfig.Certificates[i].Leaf.VerifyHostname(serverName) == nil {
					return &tlsConfig.Certificates[i], nil
				}
			}
		}
		return &tlsConfig.Certificates[0], nil
	}

	return tlsConfig, nil
}

func normalizeConfiguredHost(raw string) (string, bool, error) {
	host := strings.TrimSuffix(strings.TrimSpace(raw), ".")
	wildcard := strings.HasPrefix(host, "*.")
	if wildcard {
		host = strings.TrimPrefix(host, "*.")
	}
	if host == "" || strings.Contains(host, "*") {
		return "", false, fmt.Errorf("invalid hostname")
	}
	normalized, err := normalizeServerName(host)
	if err != nil {
		return "", false, err
	}
	return normalized, wildcard, nil
}

func normalizeServerName(raw string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(raw, "."))
	if host == "" {
		return "", nil
	}
	normalized, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", err
	}
	return strings.ToLower(normalized), nil
}
