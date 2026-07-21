package admin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/state"
)

const sessionKeySize = 32

// Session is the authenticated admin identity and its expiration time.
type Session struct {
	User string    `json:"user"`
	Exp  time.Time `json:"exp"`
}

// LoadOrCreateSessionKey loads the session signing key or creates it on first use.
func LoadOrCreateSessionKey(d *state.Dir) ([]byte, error) {
	path := d.Path("admin", "session.key")
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != sessionKeySize {
			return nil, fmt.Errorf("session key has length %d, want %d", len(key), sessionKeySize)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read session key: %w", err)
	}

	key, err = rotateSessionKey(d)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// RotateSessionKey replaces the session signing key so existing admin sessions
// become invalid, for example after a configured password changes.
func RotateSessionKey(d *state.Dir) error {
	_, err := rotateSessionKey(d)
	return err
}

func rotateSessionKey(d *state.Dir) ([]byte, error) {
	key := make([]byte, sessionKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	if err := d.WriteAtomic("admin/session.key", key, 0o600); err != nil {
		return nil, fmt.Errorf("write session key: %w", err)
	}
	return key, nil
}

// SignSession encodes and authenticates a session for use as a cookie value.
func SignSession(key []byte, s Session) string {
	payload, _ := json.Marshal(s)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)

	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// ParseSession verifies and decodes a signed, unexpired session cookie.
func ParseSession(key []byte, cookie string) (Session, bool) {
	payloadPart, macPart, ok := strings.Cut(cookie, ".")
	if !ok || payloadPart == "" || macPart == "" || strings.Contains(macPart, ".") {
		return Session{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return Session{}, false
	}
	gotMAC, err := base64.RawURLEncoding.DecodeString(macPart)
	if err != nil {
		return Session{}, false
	}

	wantMAC := hmac.New(sha256.New, key)
	_, _ = wantMAC.Write(payload)
	if !hmac.Equal(gotMAC, wantMAC.Sum(nil)) {
		return Session{}, false
	}

	var session Session
	if err := json.Unmarshal(payload, &session); err != nil || session.Exp.Before(time.Now()) {
		return Session{}, false
	}
	return session, true
}
