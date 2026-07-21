package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
)

const csrfTokenSize = 32

// NewCSRFToken returns a new random token suitable for double-submit CSRF protection.
func NewCSRFToken() string {
	token := make([]byte, csrfTokenSize)
	if _, err := rand.Read(token); err != nil {
		panic("generate CSRF token: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(token)
}

// CSRFMatch reports whether two non-empty CSRF token values match.
func CSRFMatch(cookie, header string) bool {
	if cookie == "" || header == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie), []byte(header)) == 1
}
