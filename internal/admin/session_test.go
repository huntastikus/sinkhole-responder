package admin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/state"
)

func TestSignSessionParseSessionRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	want := Session{
		User: "admin",
		Exp:  time.Now().Add(time.Hour).UTC(),
	}

	got, ok := ParseSession(key, SignSession(key, want))
	if !ok {
		t.Fatal("ParseSession() rejected a valid signed session")
	}
	if got.User != want.User || !got.Exp.Equal(want.Exp) {
		t.Fatalf("ParseSession() = %+v, want %+v", got, want)
	}
}

func TestParseSessionRejectsTampering(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	token := SignSession(key, Session{User: "admin", Exp: time.Now().Add(time.Hour)})
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		t.Fatalf("SignSession() produced %d token parts, want 2", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode signed payload: %v", err)
	}
	var session Session
	if err := json.Unmarshal(payload, &session); err != nil {
		t.Fatalf("decode signed session: %v", err)
	}
	session.User = "other"
	payload, err = json.Marshal(session)
	if err != nil {
		t.Fatalf("encode tampered session: %v", err)
	}
	tamperedPayload := base64.RawURLEncoding.EncodeToString(payload) + "." + parts[1]
	if _, ok := ParseSession(key, tamperedPayload); ok {
		t.Error("ParseSession() accepted a tampered payload")
	}

	mac, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode session MAC: %v", err)
	}
	mac[0] ^= 0xff
	tamperedMAC := parts[0] + "." + base64.RawURLEncoding.EncodeToString(mac)
	if _, ok := ParseSession(key, tamperedMAC); ok {
		t.Error("ParseSession() accepted a tampered MAC")
	}
}

func TestParseSessionRejectsExpiredSession(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	token := SignSession(key, Session{User: "admin", Exp: time.Now().Add(-time.Second)})

	if _, ok := ParseSession(key, token); ok {
		t.Error("ParseSession() accepted an expired session")
	}
}

func TestParseSessionRejectsMalformedCookie(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)

	for _, cookie := range []string{"missing-dot", "%%%.%%%"} {
		t.Run(cookie, func(t *testing.T) {
			if _, ok := ParseSession(key, cookie); ok {
				t.Errorf("ParseSession(%q) accepted a malformed cookie", cookie)
			}
		})
	}
}

func TestLoadOrCreateSessionKeyPersists(t *testing.T) {
	d, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New(): %v", err)
	}

	first, err := LoadOrCreateSessionKey(d)
	if err != nil {
		t.Fatalf("first LoadOrCreateSessionKey(): %v", err)
	}
	if len(first) != 32 {
		t.Fatalf("first key length = %d, want 32", len(first))
	}
	info, err := os.Stat(d.Path("admin", "session.key"))
	if err != nil {
		t.Fatalf("stat session key: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("session key mode = %04o, want 0600", got)
	}

	second, err := LoadOrCreateSessionKey(d)
	if err != nil {
		t.Fatalf("second LoadOrCreateSessionKey(): %v", err)
	}
	if !bytes.Equal(second, first) {
		t.Error("second LoadOrCreateSessionKey() returned a different key")
	}
}
