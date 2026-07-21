package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfiguredAdminPassword(t *testing.T) {
	for _, name := range []string{"SINKHOLE_ADMIN_PASSWORD", "SINKHOLE_ADMIN_PASSWORD_FILE"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("unset %s: %v", name, err)
		}
	}

	password, configured, err := configuredAdminPassword()
	if err != nil || configured || password != "" {
		t.Fatalf("unset configuredAdminPassword() = %q, %t, %v", password, configured, err)
	}

	t.Setenv("SINKHOLE_ADMIN_PASSWORD", "environment secret")
	password, configured, err = configuredAdminPassword()
	if err != nil || !configured || password != "environment secret" {
		t.Fatalf("environment configuredAdminPassword() = %q, %t, %v", password, configured, err)
	}

	if err := os.Unsetenv("SINKHOLE_ADMIN_PASSWORD"); err != nil {
		t.Fatal(err)
	}
	passwordFile := filepath.Join(t.TempDir(), "admin-password")
	if err := os.WriteFile(passwordFile, []byte("file secret\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SINKHOLE_ADMIN_PASSWORD_FILE", passwordFile)
	password, configured, err = configuredAdminPassword()
	if err != nil || !configured || password != "file secret" {
		t.Fatalf("file configuredAdminPassword() = %q, %t, %v", password, configured, err)
	}
}

func TestConfiguredAdminPasswordRejectsUnsafeInputs(t *testing.T) {
	tests := []struct {
		name     string
		password *string
		fileData *string
		want     string
	}{
		{name: "empty environment value", password: stringPointer(""), want: "must not be empty"},
		{name: "both sources", password: stringPointer("environment secret"), fileData: stringPointer("file secret"), want: "mutually exclusive"},
		{name: "empty file", fileData: stringPointer("\n"), want: "must not be empty"},
		{name: "oversized file", fileData: stringPointer(strings.Repeat("x", maxAdminPasswordFileBytes+1)), want: "exceeds"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, name := range []string{"SINKHOLE_ADMIN_PASSWORD", "SINKHOLE_ADMIN_PASSWORD_FILE"} {
				t.Setenv(name, "")
				if err := os.Unsetenv(name); err != nil {
					t.Fatal(err)
				}
			}
			if test.password != nil {
				t.Setenv("SINKHOLE_ADMIN_PASSWORD", *test.password)
			}
			if test.fileData != nil {
				path := filepath.Join(t.TempDir(), "admin-password")
				if err := os.WriteFile(path, []byte(*test.fileData), 0o600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("SINKHOLE_ADMIN_PASSWORD_FILE", path)
			}

			if _, _, err := configuredAdminPassword(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("configuredAdminPassword() error = %v, want %q", err, test.want)
			}
		})
	}
}

func stringPointer(value string) *string {
	return &value
}
