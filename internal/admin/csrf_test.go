package admin

import (
	"encoding/base64"
	"testing"
)

func TestCSRFMatch(t *testing.T) {
	for _, test := range []struct {
		name   string
		cookie string
		header string
		want   bool
	}{
		{name: "equal non-empty", cookie: "token", header: "token", want: true},
		{name: "mismatched", cookie: "token", header: "other", want: false},
		{name: "empty cookie", cookie: "", header: "token", want: false},
		{name: "empty header", cookie: "token", header: "", want: false},
		{name: "both empty", cookie: "", header: "", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := CSRFMatch(test.cookie, test.header); got != test.want {
				t.Errorf("CSRFMatch(%q, %q) = %t, want %t", test.cookie, test.header, got, test.want)
			}
		})
	}
}

func TestNewCSRFToken(t *testing.T) {
	first := NewCSRFToken()
	second := NewCSRFToken()
	if first == second {
		t.Fatal("NewCSRFToken() returned the same token twice")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil {
		t.Fatalf("NewCSRFToken() returned invalid base64url: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("decoded token length = %d, want 32", len(decoded))
	}
}
