package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/state"
)

const apiTokenPrefix = "srt_"

type APIToken struct {
	HashB64   string    `json:"hash_b64"`
	CreatedAt time.Time `json:"created_at"`
}

// GenerateAPIToken returns a new plaintext token and the hash-only value to persist.
func GenerateAPIToken() (plaintext string, stored APIToken, err error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", APIToken{}, fmt.Errorf("generate API token: %w", err)
	}
	plaintext = apiTokenPrefix + base64.RawURLEncoding.EncodeToString(random)
	digest := sha256.Sum256([]byte(plaintext))
	return plaintext, APIToken{
		HashB64:   base64.StdEncoding.EncodeToString(digest[:]),
		CreatedAt: time.Now().UTC(),
	}, nil
}

// LoadAPIToken reads the stored token hash. A missing file is not an error.
func LoadAPIToken(d *state.Dir) (APIToken, bool, error) {
	data, err := os.ReadFile(d.Path("admin", "api_token.json"))
	if errors.Is(err, os.ErrNotExist) {
		return APIToken{}, false, nil
	}
	if err != nil {
		return APIToken{}, false, fmt.Errorf("read API token: %w", err)
	}
	var token APIToken
	if err := json.Unmarshal(data, &token); err != nil {
		return APIToken{}, false, fmt.Errorf("decode API token: %w", err)
	}
	return token, true, nil
}

// SaveAPIToken atomically persists a token hash with owner-only permissions.
func SaveAPIToken(d *state.Dir, token APIToken) error {
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("encode API token: %w", err)
	}
	if err := d.WriteAtomic("admin/api_token.json", data, 0o600); err != nil {
		return fmt.Errorf("write API token: %w", err)
	}
	return nil
}

// DeleteAPIToken revokes the stored API token.
func DeleteAPIToken(d *state.Dir) error {
	if err := os.Remove(d.Path("admin", "api_token.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete API token: %w", err)
	}
	return nil
}

// Verify reports whether candidate matches the stored token hash.
func (t APIToken) Verify(candidate string) bool {
	want, err := base64.StdEncoding.DecodeString(t.HashB64)
	if err != nil || len(want) != sha256.Size {
		return false
	}
	got := sha256.Sum256([]byte(candidate))
	return subtle.ConstantTimeCompare(got[:], want) == 1
}
