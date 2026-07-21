package admin

import (
	"encoding/base64"
	"os"
	"testing"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/state"
)

func TestHashPasswordVerifiesPassword(t *testing.T) {
	credential, err := HashPassword("correct horse")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if credential.Algo != "pbkdf2-sha256" {
		t.Fatalf("credential algorithm = %q, want pbkdf2-sha256", credential.Algo)
	}
	if credential.Iterations < 600_000 {
		t.Fatalf("credential iterations = %d, want at least 600000", credential.Iterations)
	}
	salt, err := base64.StdEncoding.DecodeString(credential.SaltB64)
	if err != nil {
		t.Fatalf("decode credential salt: %v", err)
	}
	if len(salt) != 16 {
		t.Fatalf("credential salt length = %d, want 16", len(salt))
	}

	if !credential.Verify("correct horse") {
		t.Fatal("Credential.Verify() = false, want true")
	}
	if credential.Verify("wrong password") {
		t.Fatal("Credential.Verify() = true for wrong password, want false")
	}
}

func TestCredentialVerifyRejectsInvalidBase64(t *testing.T) {
	credential, err := HashPassword("correct horse")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	invalidSalt := credential
	invalidSalt.SaltB64 = "not-base64"
	if invalidSalt.Verify("correct horse") {
		t.Fatal("Credential.Verify() = true with invalid salt encoding, want false")
	}

	invalidHash := credential
	invalidHash.HashB64 = "not-base64"
	if invalidHash.Verify("correct horse") {
		t.Fatal("Credential.Verify() = true with invalid hash encoding, want false")
	}
}

func TestHashPasswordRejectsShortPassword(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("HashPassword() error = nil, want error")
	}
}

func TestLoadCredentialMissing(t *testing.T) {
	d := newTestStateDir(t)

	_, ok, err := LoadCredential(d)
	if err != nil {
		t.Fatalf("LoadCredential() error = %v", err)
	}
	if ok {
		t.Fatal("LoadCredential() ok = true, want false")
	}
}

func TestSaveAndLoadCredential(t *testing.T) {
	d := newTestStateDir(t)
	want, err := HashPassword("correct horse")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if err := SaveCredential(d, want); err != nil {
		t.Fatalf("SaveCredential() error = %v", err)
	}
	got, ok, err := LoadCredential(d)
	if err != nil {
		t.Fatalf("LoadCredential() error = %v", err)
	}
	if !ok {
		t.Fatal("LoadCredential() ok = false, want true")
	}
	if got != want {
		t.Fatal("LoadCredential() credential differs from saved credential")
	}

	info, err := os.Stat(d.Path("admin", "credentials.json"))
	if err != nil {
		t.Fatalf("stat credentials: %v", err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Fatalf("credentials mode = %o, want %o", got, want)
	}
}

func newTestStateDir(t *testing.T) *state.Dir {
	t.Helper()
	d, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New() error = %v", err)
	}
	return d
}
