package admin

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/huntastikus/sinkhole-responder/internal/state"
)

const (
	MinPasswordLen = 10

	credentialAlgorithm  = "pbkdf2-sha256"
	credentialIterations = 600_000
	credentialSaltSize   = 16
	credentialHashSize   = sha256.Size
)

// Credential contains the parameters and derived hash used to verify an admin password.
type Credential struct {
	Algo       string `json:"algo"`
	Iterations int    `json:"iterations"`
	SaltB64    string `json:"salt_b64"`
	HashB64    string `json:"hash_b64"`
}

// HashPassword derives a credential from pw using PBKDF2-SHA256.
func HashPassword(pw string) (Credential, error) {
	if len(pw) < MinPasswordLen {
		return Credential{}, fmt.Errorf("password must be at least %d bytes", MinPasswordLen)
	}

	salt := make([]byte, credentialSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return Credential{}, fmt.Errorf("generate password salt: %w", err)
	}
	hash, err := pbkdf2.Key(sha256.New, pw, salt, credentialIterations, credentialHashSize)
	if err != nil {
		return Credential{}, fmt.Errorf("derive password hash: %w", err)
	}

	return Credential{
		Algo:       credentialAlgorithm,
		Iterations: credentialIterations,
		SaltB64:    base64.StdEncoding.EncodeToString(salt),
		HashB64:    base64.StdEncoding.EncodeToString(hash),
	}, nil
}

// Verify reports whether pw matches the credential.
func (c Credential) Verify(pw string) bool {
	if c.Algo != credentialAlgorithm || c.Iterations < credentialIterations {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(c.SaltB64)
	if err != nil || len(salt) != credentialSaltSize {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(c.HashB64)
	if err != nil || len(want) != credentialHashSize {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, c.Iterations, credentialHashSize)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// LoadCredential reads the persisted admin credential. A missing file is not an error.
func LoadCredential(d *state.Dir) (Credential, bool, error) {
	data, err := os.ReadFile(d.Path("admin", "credentials.json"))
	if errors.Is(err, os.ErrNotExist) {
		return Credential{}, false, nil
	}
	if err != nil {
		return Credential{}, false, fmt.Errorf("read admin credential: %w", err)
	}

	var credential Credential
	if err := json.Unmarshal(data, &credential); err != nil {
		return Credential{}, false, fmt.Errorf("decode admin credential: %w", err)
	}
	return credential, true, nil
}

// SaveCredential atomically persists the admin credential with owner-only permissions.
func SaveCredential(d *state.Dir, c Credential) error {
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("encode admin credential: %w", err)
	}
	if err := d.WriteAtomic("admin/credentials.json", data, 0o600); err != nil {
		return fmt.Errorf("write admin credential: %w", err)
	}
	return nil
}
