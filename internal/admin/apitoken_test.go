package admin

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/huntastikus/sinkhole-responder/internal/state"
)

func TestAPITokenRoundTrip(t *testing.T) {
	d, err := state.New(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, stored, err := GenerateAPIToken()
	if err != nil {
		t.Fatalf("GenerateAPIToken: %v", err)
	}
	if !strings.HasPrefix(plaintext, "srt_") {
		t.Fatalf("token = %q, want srt_ prefix", plaintext)
	}
	if !stored.Verify(plaintext) || stored.Verify("garbage") {
		t.Fatal("generated token verification failed")
	}
	if err := SaveAPIToken(d, stored); err != nil {
		t.Fatalf("SaveAPIToken: %v", err)
	}
	loaded, present, err := LoadAPIToken(d)
	if err != nil || !present {
		t.Fatalf("LoadAPIToken: present=%v err=%v", present, err)
	}
	if !loaded.Verify(plaintext) {
		t.Fatal("loaded token does not verify plaintext")
	}
	if err := DeleteAPIToken(d); err != nil {
		t.Fatalf("DeleteAPIToken: %v", err)
	}
	if _, present, err := LoadAPIToken(d); err != nil || present {
		t.Fatalf("token after delete: present=%v err=%v", present, err)
	}
}
