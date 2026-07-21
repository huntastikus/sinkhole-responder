package admin

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/config"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/tlsx"
)

const (
	tlsUploadFileLimit = int64(64 << 10)
	tlsUploadBodyLimit = int64(200 << 10)
	defaultCAName      = "Sinkhole Responder Local CA"
	defaultCAYears     = 5
	caWarning          = "This CA can impersonate ANY HTTPS site to clients that trust it. Use only in an isolated lab/home environment; never distribute it or install it system-wide."
)

var errTLSUploadTooLarge = errors.New("TLS upload exceeds 64 KiB")

type tlsCertificateMetadata struct {
	CertPath    string `json:"cert_path"`
	Fingerprint string `json:"fingerprint"`
	Subject     string `json:"subject"`
	NotAfter    string `json:"not_after"`
}

type tlsStaticCertificateMetadata struct {
	Hosts       []string `json:"hosts"`
	CertFile    string   `json:"cert_file"`
	Subject     string   `json:"subject"`
	NotAfter    string   `json:"not_after"`
	Fingerprint string   `json:"fingerprint"`
}

type tlsStatusResponse struct {
	Mode        string                         `json:"mode"`
	ListenHTTPS []string                       `json:"listen_https"`
	CA          *tlsCertificateMetadata        `json:"ca"`
	StaticCerts []tlsStaticCertificateMetadata `json:"static_certs"`
}

type generateCARequest struct {
	CN    string `json:"cn"`
	Years int    `json:"years"`
}

type tlsModeCertificateRequest struct {
	Hosts    []string `json:"hosts"`
	CertFile string   `json:"cert_file"`
	KeyFile  string   `json:"key_file"`
}

type tlsModeRequest struct {
	Mode        string                      `json:"mode"`
	Mtime       jsonInt64                   `json:"mtime"`
	StaticCerts []tlsModeCertificateRequest `json:"static_certs"`
	CACert      string                      `json:"ca_cert"`
	CAKey       string                      `json:"ca_key"`
	HTTPSListen []string                    `json:"https_listen"`
}

func (s *Server) handleTLSStatus(w http.ResponseWriter, _ *http.Request) {
	cfg := s.deps.Cfg()

	response := tlsStatusResponse{
		Mode:        cfg.TLS.Mode,
		ListenHTTPS: append([]string{}, cfg.Listen.HTTPS...),
		StaticCerts: make([]tlsStaticCertificateMetadata, 0, len(cfg.TLS.Static.Certs)),
	}
	caPath, err := s.caCertificatePath(cfg)
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if caPath != "" {
		metadata, err := certificateMetadata(caPath)
		if err != nil {
			writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("read CA certificate metadata: %v", err))
			return
		}
		response.CA = &metadata
	}

	for _, pair := range cfg.TLS.Static.Certs {
		metadata, err := certificateMetadata(pair.CertFile)
		if err != nil {
			continue
		}
		response.StaticCerts = append(response.StaticCerts, tlsStaticCertificateMetadata{
			Hosts:       append([]string{}, pair.Hosts...),
			CertFile:    pair.CertFile,
			Subject:     metadata.Subject,
			NotAfter:    metadata.NotAfter,
			Fingerprint: metadata.Fingerprint,
		})
	}

	writeConfigJSON(w, http.StatusOK, response)
}

func (s *Server) handleGenerateCA(w http.ResponseWriter, r *http.Request) {
	var request generateCARequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		writeConfigError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err))
		return
	}
	request.CN = strings.TrimSpace(request.CN)
	if request.CN == "" {
		request.CN = defaultCAName
	}
	if request.Years == 0 {
		request.Years = defaultCAYears
	}
	if request.Years < 1 || request.Years > 100 {
		writeConfigError(w, http.StatusBadRequest, "years must be between 1 and 100")
		return
	}

	dir := s.deps.State.Path("tls")
	if dir == "" {
		writeConfigError(w, http.StatusInternalServerError, "TLS state path is unavailable")
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("create TLS state directory: %v", err))
		return
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("secure TLS state directory: %v", err))
		return
	}
	certPath := filepath.Join(dir, "ca.cert.pem")
	keyPath := filepath.Join(dir, "ca.key.pem")
	// A CA may already exist (auto-generated at boot). Reuse it rather than
	// refuse to overwrite; only generate when none is present.
	if _, statErr := os.Stat(certPath); errors.Is(statErr, os.ErrNotExist) {
		if _, _, err := tlsx.CreateCA(dir, request.CN, request.Years); err != nil {
			writeConfigError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else if statErr != nil {
		writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("inspect CA certificate: %v", statErr))
		return
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("read CA certificate: %v", err))
		return
	}
	fingerprint, err := certFingerprint(certPEM)
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("fingerprint generated CA certificate: %v", err))
		return
	}
	writeConfigJSON(w, http.StatusOK, map[string]string{
		"fingerprint": fingerprint,
		"cert_path":   certPath,
		"key_path":    keyPath,
		"warning":     caWarning,
	})
}

func (s *Server) handleTLSUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, tlsUploadBodyLimit)
	if err := r.ParseMultipartForm(tlsUploadFileLimit); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeConfigError(w, http.StatusRequestEntityTooLarge, "certificate or key exceeds 64 KiB")
			return
		}
		writeConfigError(w, http.StatusBadRequest, "invalid multipart upload")
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}

	certPEM, err := readTLSUploadFile(r, "cert")
	if errors.Is(err, errTLSUploadTooLarge) {
		writeConfigError(w, http.StatusRequestEntityTooLarge, "certificate or key exceeds 64 KiB")
		return
	}
	if err != nil {
		writeConfigError(w, http.StatusBadRequest, "certificate upload is required")
		return
	}
	keyPEM, err := readTLSUploadFile(r, "key")
	if errors.Is(err, errTLSUploadTooLarge) {
		writeConfigError(w, http.StatusRequestEntityTooLarge, "certificate or key exceeds 64 KiB")
		return
	}
	if err != nil {
		writeConfigError(w, http.StatusBadRequest, "key upload is required")
		return
	}

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		writeConfigError(w, http.StatusBadRequest, "certificate and key do not match or are invalid")
		return
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		writeConfigError(w, http.StatusBadRequest, "certificate and key do not match or are invalid")
		return
	}
	hosts := parseTLSHosts(r.FormValue("hosts"))
	if len(hosts) == 0 {
		hosts = append([]string{}, leaf.DNSNames...)
	}
	fingerprint, err := certFingerprint(certPEM)
	if err != nil {
		writeConfigError(w, http.StatusBadRequest, "certificate and key do not match or are invalid")
		return
	}

	uploadDir := s.deps.State.Path("tls", "uploaded")
	if uploadDir == "" {
		writeConfigError(w, http.StatusInternalServerError, "TLS upload state path is unavailable")
		return
	}
	if err := os.MkdirAll(uploadDir, 0o700); err != nil {
		writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("create TLS upload directory: %v", err))
		return
	}
	if err := os.Chmod(uploadDir, 0o700); err != nil {
		writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("secure TLS upload directory: %v", err))
		return
	}
	baseName := tlsUploadBaseName(hosts, fingerprint)
	certName := baseName + ".cert.pem"
	keyName := baseName + ".key.pem"
	certPath := s.deps.State.Path("tls", "uploaded", certName)
	keyPath := s.deps.State.Path("tls", "uploaded", keyName)
	if certPath == "" || keyPath == "" {
		writeConfigError(w, http.StatusInternalServerError, "TLS upload path is unavailable")
		return
	}
	if err := s.deps.State.WriteAtomic(filepath.Join("tls", "uploaded", certName), certPEM, 0o644); err != nil {
		writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("write uploaded certificate: %v", err))
		return
	}
	if err := s.deps.State.WriteAtomic(filepath.Join("tls", "uploaded", keyName), keyPEM, 0o600); err != nil {
		writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("write uploaded key: %v", err))
		return
	}

	writeConfigJSON(w, http.StatusOK, map[string]any{
		"hosts":       hosts,
		"cert_path":   certPath,
		"key_path":    keyPath,
		"fingerprint": fingerprint,
	})
}

func (s *Server) handleTLSMode(w http.ResponseWriter, r *http.Request) {
	var request tlsModeRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeConfigError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err))
		return
	}
	switch request.Mode {
	case "disabled", "static", "local-ca":
	default:
		writeConfigError(w, http.StatusBadRequest, "mode must be disabled, static, or local-ca")
		return
	}
	s.mutateConfig(w, request.Mtime, func(clone *config.Config) error {
		clone.TLS.Mode = request.Mode
		switch request.Mode {
		case "static":
			clone.TLS.Static.Certs = make([]config.CertPair, 0, len(request.StaticCerts))
			for _, pair := range request.StaticCerts {
				clone.TLS.Static.Certs = append(clone.TLS.Static.Certs, config.CertPair{
					Hosts:    append([]string{}, pair.Hosts...),
					CertFile: pair.CertFile,
					KeyFile:  pair.KeyFile,
				})
			}
		case "local-ca":
			clone.TLS.LocalCA.CACert = request.CACert
			clone.TLS.LocalCA.CAKey = request.CAKey
		case "disabled":
			clone.Listen.HTTPS = []string{}
		}
		if request.HTTPSListen != nil {
			clone.Listen.HTTPS = append([]string{}, request.HTTPSListen...)
		}
		return nil
	}, map[string]any{
		"restart_required": true,
	})
}

func (s *Server) handleCADownload(w http.ResponseWriter, _ *http.Request) {
	cfg := s.deps.Cfg()
	certPath, err := s.caCertificatePath(cfg)
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if certPath == "" {
		writeConfigError(w, http.StatusNotFound, "no CA certificate available")
		return
	}
	contents, err := os.ReadFile(certPath)
	if errors.Is(err, os.ErrNotExist) {
		writeConfigError(w, http.StatusNotFound, "no CA certificate available")
		return
	}
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, fmt.Sprintf("read CA certificate: %v", err))
		return
	}
	publicPEM, err := publicCertificatePEM(contents)
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, "CA certificate file is invalid")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="sinkhole-ca.crt"`)
	_, _ = w.Write(publicPEM)
}

func (s *Server) caCertificatePath(cfg *config.Config) (string, error) {
	if s.deps.State == nil {
		return "", errors.New("TLS state path is unavailable")
	}
	certPath, _ := tlsx.ResolveCAPaths(cfg.TLS.LocalCA, s.deps.State.Root)
	if _, err := os.Stat(certPath); err == nil {
		return certPath, nil
	} else if errors.Is(err, os.ErrNotExist) {
		return "", nil
	} else {
		return "", fmt.Errorf("inspect CA certificate: %w", err)
	}
}

func readTLSUploadFile(r *http.Request, field string) ([]byte, error) {
	file, _, err := r.FormFile(field)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, tlsUploadFileLimit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > tlsUploadFileLimit {
		return nil, errTLSUploadTooLarge
	}
	return contents, nil
}

func parseTLSHosts(raw string) []string {
	parts := strings.Split(raw, ",")
	hosts := make([]string, 0, len(parts))
	for _, part := range parts {
		if host := strings.TrimSpace(part); host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

func tlsUploadBaseName(hosts []string, fingerprint string) string {
	if len(hosts) > 0 {
		if slug := tlsFilenameSlug(hosts[0]); slug != "" {
			return slug
		}
	}
	stable := strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
	if len(stable) > 16 {
		stable = stable[:16]
	}
	return "certificate-" + stable
}

func tlsFilenameSlug(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	var slug strings.Builder
	lastDash := false
	for _, char := range host {
		allowed := char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '.' || char == '_' || char == '-'
		if allowed {
			slug.WriteRune(char)
			lastDash = false
		} else if !lastDash {
			slug.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(slug.String(), ".-_")
}

func certificateMetadata(path string) (tlsCertificateMetadata, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return tlsCertificateMetadata{}, err
	}
	certificate, err := firstCertificate(contents)
	if err != nil {
		return tlsCertificateMetadata{}, err
	}
	fingerprint, err := certFingerprint(contents)
	if err != nil {
		return tlsCertificateMetadata{}, err
	}
	return tlsCertificateMetadata{
		CertPath:    path,
		Fingerprint: fingerprint,
		Subject:     certificate.Subject.CommonName,
		NotAfter:    certificate.NotAfter.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}, nil
}

func firstCertificate(pemBytes []byte) (*x509.Certificate, error) {
	remaining := pemBytes
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type == "CERTIFICATE" {
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}
			return certificate, nil
		}
	}
	return nil, errors.New("no CERTIFICATE PEM block found")
}

func certFingerprint(pemBytes []byte) (string, error) {
	certificate, err := firstCertificate(pemBytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(certificate.Raw)
	parts := make([]string, len(sum))
	for index, value := range sum {
		parts[index] = fmt.Sprintf("%02X", value)
	}
	return strings.Join(parts, ":"), nil
}

func publicCertificatePEM(contents []byte) ([]byte, error) {
	remaining := contents
	var publicPEM []byte
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type == "CERTIFICATE" {
			publicPEM = append(publicPEM, pem.EncodeToMemory(block)...)
		}
	}
	if len(publicPEM) == 0 {
		return nil, errors.New("no CERTIFICATE PEM block found")
	}
	return publicPEM, nil
}
