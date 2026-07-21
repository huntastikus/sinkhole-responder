package rules

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func FuzzHostNormalizeAndMatch(f *testing.F) {
	for _, host := range []string{
		"example.com",
		"bücher.example",
		"xn--bcher-kva.example",
		"example.com.",
		"example.com:8080",
		"[2001:db8::1]",
		"[2001:db8::1]:443",
		"",
		":",
		"[[[",
		strings.Repeat("a", 64<<10),
		"a\x00b",
		"xn--",
		"%00",
	} {
		f.Add(host)
	}

	engine, err := Compile([]Rule{
		{Name: "exact", Host: "example.com"},
		{Name: "glob", HostGlob: "*.x"},
		{Name: "path", PathGlob: "/ads/*"},
	}, f.TempDir())
	if err != nil {
		f.Fatalf("compile fixed rules: %v", err)
	}

	f.Fuzz(func(t *testing.T, host string) {
		request := httptest.NewRequest(http.MethodGet, "http://placeholder.test/ads/pixel", nil)
		request.Host = host
		_, _ = engine.Match(request)
	})
}

func FuzzRuleCompile(f *testing.F) {
	for _, rulesYAML := range [][]byte{
		[]byte("- name: exact\n  host: example.com\n  response:\n    status: 200\n"),
		[]byte("- path_glob: /assets/*\n  response:\n    body: ok\n"),
		[]byte("["),
		[]byte("- path_regex: '['\n"),
		[]byte("- path_glob: '/*'\n  response:\n    body_file: ../../etc/passwd\n"),
		[]byte("- path_glob: '/*'\n  response:\n    body: " + strings.Repeat("x", 64<<10) + "\n"),
		[]byte("- path_glob: '/*'\n  response:\n    body: " + strings.Repeat("[", 128) + "x" + strings.Repeat("]", 128) + "\n"),
	} {
		f.Add(rulesYAML)
	}

	configDir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		var configured []Rule
		_ = yaml.Unmarshal(data, &configured)
		_, _ = Compile(configured, configDir)
	})
}
