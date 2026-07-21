package tlsx

import (
	"path/filepath"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/config"
)

// ResolveCAPaths returns the CA cert/key paths: the configured paths if set,
// otherwise the default generated location under the state dir.
func ResolveCAPaths(localCA config.TLSLocalCA, stateDir string) (certPath, keyPath string) {
	if localCA.CACert != "" && localCA.CAKey != "" {
		return localCA.CACert, localCA.CAKey
	}
	return filepath.Join(stateDir, "tls", "ca.cert.pem"), filepath.Join(stateDir, "tls", "ca.key.pem")
}
