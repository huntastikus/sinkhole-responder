package rules

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/idna"
)

func TestMatchReturnsFirstMatchingRule(t *testing.T) {
	engine := mustCompile(t, []Rule{
		{Name: "first", Host: "ads.example.com"},
		{Name: "second", Host: "ads.example.com"},
	})

	got, ok := engine.Match(request(t, http.MethodGet, "http://ads.example.com/", "", nil))
	if !ok || got.Name != "first" {
		t.Fatalf("Match() = (%v, %v), want first rule", got, ok)
	}
	if engine.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", engine.Len())
	}
}

func TestHostMatching(t *testing.T) {
	punycode, err := idna.Lookup.ToASCII("bücher.example")
	if err != nil {
		t.Fatalf("ToASCII: %v", err)
	}
	unicodeHost, err := idna.Lookup.ToUnicode(punycode)
	if err != nil {
		t.Fatalf("ToUnicode: %v", err)
	}

	tests := []struct {
		name        string
		ruleHost    string
		requestHost string
	}{
		{name: "case insensitive and port stripped", ruleHost: "Ads.Example.COM", requestHost: "ads.example.com:8080"},
		{name: "unicode rule to punycode request", ruleHost: "bücher.example", requestHost: punycode},
		{name: "punycode rule to unicode request", ruleHost: punycode, requestHost: strings.ToUpper(unicodeHost)},
		{name: "trailing dot stripped", ruleHost: "ads.example.com", requestHost: "ads.example.com."},
		{name: "bracketed IPv6 with port", ruleHost: "2001:db8::1", requestHost: "[2001:db8::1]:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := mustCompile(t, []Rule{{Name: "match", Host: tt.ruleHost}})
			got, ok := engine.Match(request(t, http.MethodGet, "http://placeholder/", tt.requestHost, nil))
			if !ok || got.Name != "match" {
				t.Fatalf("Match() = (%v, %v), want match for host %q", got, ok, tt.requestHost)
			}
		})
	}
}

func TestHostGlob(t *testing.T) {
	engine := mustCompile(t, []Rule{{Name: "glob", HostGlob: "*.doubleclick.net"}})

	if _, ok := engine.Match(request(t, http.MethodGet, "http://stats.doubleclick.net/", "", nil)); !ok {
		t.Fatal("Match() did not match subdomain")
	}
	if _, ok := engine.Match(request(t, http.MethodGet, "http://doubleclick.net/", "", nil)); ok {
		t.Fatal("Match() matched bare domain")
	}
}

func TestPathMatchers(t *testing.T) {
	engine := mustCompile(t, []Rule{
		{Name: "glob", PathGlob: "/ads/*"},
		{Name: "regex", PathRegex: `^/sdk/.+\.js$`},
	})

	tests := []struct {
		path string
		name string
		ok   bool
	}{
		{path: "/ads/banner.png", name: "glob", ok: true},
		{path: "/sdk/client.js", name: "regex", ok: true},
		{path: "/sdk/.js", ok: false},
		{path: "/content/banner.png", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, ok := engine.Match(request(t, http.MethodGet, "http://example.com"+tt.path, "", nil))
			if ok != tt.ok {
				t.Fatalf("Match() ok = %v, want %v", ok, tt.ok)
			}
			if ok && got.Name != tt.name {
				t.Fatalf("Match().Name = %q, want %q", got.Name, tt.name)
			}
		})
	}
}

func TestRequestCriteria(t *testing.T) {
	tests := []struct {
		name      string
		rule      Rule
		method    string
		headers   map[string]string
		wantMatch bool
	}{
		{name: "method case insensitive", rule: Rule{Method: "get"}, method: "GET", wantMatch: true},
		{name: "method mismatch", rule: Rule{Method: "GET"}, method: "POST", wantMatch: false},
		{name: "fetch destination case insensitive", rule: Rule{SecFetchDest: "image"}, method: "GET", headers: map[string]string{"Sec-Fetch-Dest": "IMAGE"}, wantMatch: true},
		{name: "fetch destination mismatch", rule: Rule{SecFetchDest: "image"}, method: "GET", headers: map[string]string{"Sec-Fetch-Dest": "empty"}, wantMatch: false},
		{name: "accept substring case insensitive", rule: Rule{Accept: "IMAGE/"}, method: "GET", headers: map[string]string{"Accept": "image/avif,image/webp"}, wantMatch: true},
		{name: "accept mismatch", rule: Rule{Accept: "text/html"}, method: "GET", headers: map[string]string{"Accept": "image/webp"}, wantMatch: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := mustCompile(t, []Rule{tt.rule})
			_, ok := engine.Match(request(t, tt.method, "http://example.com/", "", tt.headers))
			if ok != tt.wantMatch {
				t.Fatalf("Match() ok = %v, want %v", ok, tt.wantMatch)
			}
		})
	}
}

func TestQueryCriteria(t *testing.T) {
	tests := []struct {
		name      string
		query     map[string]string
		url       string
		wantMatch bool
	}{
		{name: "presence with value", query: map[string]string{"utm_source": ""}, url: "http://example.com/?utm_source=x", wantMatch: true},
		{name: "presence with empty value", query: map[string]string{"utm_source": ""}, url: "http://example.com/?utm_source=", wantMatch: true},
		{name: "presence missing", query: map[string]string{"utm_source": ""}, url: "http://example.com/", wantMatch: false},
		{name: "exact value", query: map[string]string{"v": "2"}, url: "http://example.com/?v=2", wantMatch: true},
		{name: "wrong value", query: map[string]string{"v": "2"}, url: "http://example.com/?v=3", wantMatch: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := mustCompile(t, []Rule{{Query: tt.query}})
			_, ok := engine.Match(request(t, http.MethodGet, tt.url, "", nil))
			if ok != tt.wantMatch {
				t.Fatalf("Match() ok = %v, want %v", ok, tt.wantMatch)
			}
		})
	}
}

func TestHeaderCriteriaCanonicalizeConfiguredName(t *testing.T) {
	tests := []struct {
		name      string
		criteria  map[string]string
		headers   map[string]string
		wantMatch bool
	}{
		{name: "presence", criteria: map[string]string{"x-requested-with": ""}, headers: map[string]string{"X-Requested-With": "anything"}, wantMatch: true},
		{name: "exact value", criteria: map[string]string{"x-requested-with": "XMLHttpRequest"}, headers: map[string]string{"X-Requested-With": "XMLHttpRequest"}, wantMatch: true},
		{name: "wrong value", criteria: map[string]string{"x-requested-with": "XMLHttpRequest"}, headers: map[string]string{"X-Requested-With": "fetch"}, wantMatch: false},
		{name: "missing", criteria: map[string]string{"x-requested-with": ""}, wantMatch: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := mustCompile(t, []Rule{{Headers: tt.criteria}})
			_, ok := engine.Match(request(t, http.MethodGet, "http://example.com/", "", tt.headers))
			if ok != tt.wantMatch {
				t.Fatalf("Match() ok = %v, want %v", ok, tt.wantMatch)
			}
		})
	}
}

func TestCompileValidationErrors(t *testing.T) {
	configDir := t.TempDir()
	tests := []struct {
		name    string
		rule    Rule
		wantErr string
	}{
		{name: "no criteria", rule: Rule{Name: "broken"}, wantErr: "match criterion"},
		{name: "two body sources", rule: Rule{Name: "broken", PathGlob: "/*", Response: Response{Body: "a", BodyBase64: "Yg=="}}, wantErr: "at most one"},
		{name: "bad base64", rule: Rule{Name: "broken", PathGlob: "/*", Response: Response{BodyBase64: "%%%"}}, wantErr: "body_base64"},
		{name: "unknown embedded", rule: Rule{Name: "broken", PathGlob: "/*", Response: Response{Embedded: "missing"}}, wantErr: "unknown embedded"},
		{name: "bad regex", rule: Rule{Name: "broken", PathRegex: "["}, wantErr: "path_regex"},
		{name: "bad path glob", rule: Rule{Name: "broken", PathGlob: "["}, wantErr: "path_glob"},
		{name: "bad host glob", rule: Rule{Name: "broken", HostGlob: "["}, wantErr: "host_glob"},
		{name: "relative traversal", rule: Rule{Name: "broken", PathGlob: "/*", Response: Response{BodyFile: "../../etc/passwd"}}, wantErr: "escapes config directory"},
		{name: "absolute traversal", rule: Rule{Name: "broken", PathGlob: "/*", Response: Response{BodyFile: "/etc/passwd"}}, wantErr: "escapes config directory"},
		{name: "delay too high", rule: Rule{Name: "broken", PathGlob: "/*", Response: Response{DelayMS: 20000}}, wantErr: "delay_ms"},
		{name: "delay negative", rule: Rule{Name: "broken", PathGlob: "/*", Response: Response{DelayMS: -1}}, wantErr: "delay_ms"},
		{name: "status invalid", rule: Rule{Name: "broken", PathGlob: "/*", Response: Response{Status: 42}}, wantErr: "status"},
		{name: "method unsupported", rule: Rule{Name: "broken", Method: "BREW"}, wantErr: "method"},
		{name: "host empty after normalization", rule: Rule{Name: "broken", Host: "."}, wantErr: "empty after normalization"},
		{name: "content length header", rule: Rule{Name: "broken", PathGlob: "/*", Response: Response{Headers: map[string]string{"Content-Length": "4"}}}, wantErr: `response header "Content-Length" is not allowed`},
		{name: "transfer encoding header case insensitive", rule: Rule{Name: "broken", PathGlob: "/*", Response: Response{Headers: map[string]string{"transfer-encoding": "chunked"}}}, wantErr: `response header "transfer-encoding" is not allowed`},
		{name: "connection header case insensitive", rule: Rule{Name: "broken", PathGlob: "/*", Response: Response{Headers: map[string]string{"CONNECTION": "close"}}}, wantErr: `response header "CONNECTION" is not allowed`},
		{name: "invalid header name", rule: Rule{Name: "broken", PathGlob: "/*", Response: Response{Headers: map[string]string{"Bad Header": "value"}}}, wantErr: `response header "Bad Header" has an invalid field name`},
		{name: "invalid header value", rule: Rule{Name: "broken", PathGlob: "/*", Response: Response{Headers: map[string]string{"X-Test": "value\r\nInjected: true"}}}, wantErr: `response header "X-Test" has an invalid field value`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Compile([]Rule{tt.rule}, configDir)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Compile() error = %v, want error containing %q", err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), `rule 0 ("broken")`) {
				t.Fatalf("Compile() error = %v, want rule index and name", err)
			}
		})
	}
}

func TestCompileRejectsOversizeBodyFile(t *testing.T) {
	configDir := t.TempDir()
	path := filepath.Join(configDir, "large.bin")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxBodyFileSize+1), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := Compile([]Rule{{PathGlob: "/*", Response: Response{BodyFile: "large.bin"}}}, configDir)
	if err == nil || !strings.Contains(err.Error(), "exceeds 1 MiB") {
		t.Fatalf("Compile() error = %v, want size limit error", err)
	}
}

func TestCompileLoadsBodyFile(t *testing.T) {
	configDir := t.TempDir()
	want := []byte("file body\x00contents")
	if err := os.WriteFile(filepath.Join(configDir, "body.bin"), want, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	engine := mustCompileInDir(t, []Rule{{PathGlob: "/*", Response: Response{BodyFile: "body.bin"}}}, configDir)
	got, ok := engine.Match(request(t, http.MethodGet, "http://example.com/", "", nil))
	if !ok {
		t.Fatal("Match() did not match")
	}
	if !got.HasBody || !bytes.Equal(got.Body, want) {
		t.Fatalf("compiled body = (%q, HasBody %v), want %q", got.Body, got.HasBody, want)
	}

	if err := os.WriteFile(filepath.Join(configDir, "body.bin"), []byte("changed"), 0o600); err != nil {
		t.Fatalf("rewrite body file: %v", err)
	}
	if !bytes.Equal(got.Body, want) {
		t.Fatalf("compiled body changed after file rewrite: %q", got.Body)
	}
}

func TestBodyFileSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	outside := filepath.Join(root, "outside.bin")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(configDir, "body.bin")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, err := Compile([]Rule{{PathGlob: "/*", Response: Response{BodyFile: "body.bin"}}}, configDir)
	if err == nil || !strings.Contains(err.Error(), "escapes config directory") {
		t.Fatalf("Compile() error = %v, want containment error", err)
	}
}

func TestCompileEmbeddedAsset(t *testing.T) {
	tests := []struct {
		name            string
		contentType     string
		wantContentType string
	}{
		{name: "asset content type", wantContentType: "image/gif"},
		{name: "explicit override", contentType: "application/octet-stream", wantContentType: "application/octet-stream"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := mustCompile(t, []Rule{{
				PathGlob: "/*",
				Response: Response{Embedded: "transparent-gif", ContentType: tt.contentType},
			}})
			got, ok := engine.Match(request(t, http.MethodGet, "http://example.com/", "", nil))
			if !ok {
				t.Fatal("Match() did not match")
			}
			if !got.HasBody || len(got.Body) != 43 || got.ContentType != tt.wantContentType {
				t.Fatalf("compiled asset = len %d, HasBody %v, ContentType %q", len(got.Body), got.HasBody, got.ContentType)
			}
		})
	}
}

func TestCompiledHasBody(t *testing.T) {
	tests := []struct {
		name    string
		body    Response
		want    bool
		wantLen int
	}{
		{name: "no body source", body: Response{}, want: false},
		{name: "empty body string is unset", body: Response{Body: ""}, want: false},
		{name: "non-empty body", body: Response{Body: "x"}, want: true, wantLen: 1},
		{name: "empty embedded asset", body: Response{Embedded: "empty-text"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := mustCompile(t, []Rule{{PathGlob: "/*", Response: tt.body}})
			got, ok := engine.Match(request(t, http.MethodGet, "http://example.com/", "", nil))
			if !ok {
				t.Fatal("Match() did not match")
			}
			if got.HasBody != tt.want || len(got.Body) != tt.wantLen {
				t.Fatalf("compiled body = len %d, HasBody %v; want len %d, HasBody %v", len(got.Body), got.HasBody, tt.wantLen, tt.want)
			}
		})
	}
}

func TestCompileResponseMetadata(t *testing.T) {
	engine := mustCompile(t, []Rule{{
		Name:     "metadata",
		PathGlob: "/*",
		Response: Response{
			Status:      204,
			ContentType: "text/plain",
			Headers:     map[string]string{"Cache-Control": "no-store"},
			DelayMS:     250,
		},
	}})
	got, ok := engine.Match(request(t, http.MethodGet, "http://example.com/", "", nil))
	if !ok {
		t.Fatal("Match() did not match")
	}
	if got.Status != 204 || got.ContentType != "text/plain" || got.Headers["Cache-Control"] != "no-store" || got.Delay != 250*time.Millisecond {
		t.Fatalf("compiled metadata = %#v", got)
	}
}

func TestCompileResponseHeadersCanonicalizedAndDeduplicated(t *testing.T) {
	engine := mustCompile(t, []Rule{{
		PathGlob: "/*",
		Response: Response{Headers: map[string]string{
			"X-CUSTOM":   "first",
			"x-custom":   "last",
			"set-cookie": "forbidden=1",
		}},
	}})
	got, ok := engine.Match(request(t, http.MethodGet, "http://example.com/", "", nil))
	if !ok {
		t.Fatal("Match() did not match")
	}
	want := map[string]string{"X-Custom": "last"}
	if !reflect.DeepEqual(got.Headers, want) {
		t.Fatalf("compiled headers = %#v, want %#v", got.Headers, want)
	}
}

func TestMatchNeverPanicsOnGarbageHost(t *testing.T) {
	engine := mustCompile(t, []Rule{{Host: "safe.example"}})
	hosts := []string{"", ":", "[[[", strings.Repeat("x", 64<<10)}
	for _, host := range hosts {
		t.Run(hostName(host), func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("Match() panicked for host length %d: %v", len(host), recovered)
				}
			}()
			r := request(t, http.MethodGet, "http://example.com/", host, nil)
			r.Host = host
			engine.Match(r)
		})
	}

	if _, ok := (*Engine)(nil).Match(nil); ok {
		t.Fatal("nil engine/request unexpectedly matched")
	}
}

func BenchmarkMatchNoHostCriteria(b *testing.B) {
	rules := make([]Rule, 50)
	for i := range rules {
		rules[i] = Rule{PathGlob: "/never-match"}
	}
	engine, err := Compile(rules, b.TempDir())
	if err != nil {
		b.Fatalf("Compile() error = %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://example.com/request", nil)
	r.Host = strings.Repeat("x", 60<<10)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, ok := engine.Match(r); ok {
			b.Fatal("Match() unexpectedly matched")
		}
	}
}

func mustCompile(t *testing.T, rules []Rule) *Engine {
	t.Helper()
	return mustCompileInDir(t, rules, t.TempDir())
}

func mustCompileInDir(t *testing.T, rules []Rule, configDir string) *Engine {
	t.Helper()
	engine, err := Compile(rules, configDir)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	return engine
}

func request(t *testing.T, method, target, host string, headers map[string]string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	if host != "" {
		r.Host = host
	}
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	return r
}

func hostName(host string) string {
	if len(host) > 40 {
		return "very long"
	}
	if host == "" {
		return "empty"
	}
	return host
}

func TestGlobMatchDoublestar(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		want    bool
	}{
		{"root level", "**/tag/js/gpt.js", "/tag/js/gpt.js", true},
		{"one level deep", "**/tag/js/gpt.js", "/a/tag/js/gpt.js", true},
		{"two levels deep", "**/tag/js/gpt.js", "/a/b/tag/js/gpt.js", true},
		{"suffix mismatch", "**/tag/js/gpt.js", "/a/b/tag/js/other.js", false},
		{"doublestar middle", "/assets/**/app.js", "/assets/v1/2024/app.js", true},
		{"doublestar middle zero segments", "/assets/**/app.js", "/assets/app.js", true},
		{"doublestar with glob segment", "**/gpt/*.js", "/x/y/gpt/pubads_impl.js", true},
		{"doublestar with glob segment deep tail", "**/gpt/*.js", "/x/gpt/deeper/pubads.js", false},
		{"bare doublestar", "**", "/anything/at/all", true},
		{"no doublestar unchanged", "/ads/*", "/ads/pixel", true},
		{"no doublestar still not recursive", "/ads/*", "/ads/a/pixel", false},
		{"mid-segment stars are not special", "/a**b", "/axxb", true},
		{"mid-segment stars do not recurse", "/a**b", "/a/x/b", false},
		{"trailing doublestar", "/static/**", "/static/js/vendor/x.js", true},
		{"trailing doublestar zero segments", "/static/**", "/static", true},
		{"host glob doublestar", "**", "cdn.example.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := globMatch(tt.pattern, tt.input); got != tt.want {
				t.Fatalf("globMatch(%q, %q) = %v, want %v", tt.pattern, tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateGlobRejectsBadSegmentAfterDoublestar(t *testing.T) {
	if err := validateGlob("**/["); err == nil {
		t.Fatal("expected error for bad segment after **, got nil")
	}
	if err := validateGlob("**/tag/js/gpt.js"); err != nil {
		t.Fatalf("valid pattern rejected: %v", err)
	}
	if err := validateGlob("/ads/["); err == nil {
		t.Fatal("expected error for bad plain pattern, got nil")
	}
}

func TestCompileRejectsBadGlobAfterDoublestar(t *testing.T) {
	_, err := Compile([]Rule{{PathGlob: "**/[", Response: Response{Body: "x"}}}, t.TempDir())
	if err == nil {
		t.Fatal("expected compile error for path_glob with bad segment after **")
	}
}

func TestEngineMatchesDeepDoublestarPath(t *testing.T) {
	engine, err := Compile([]Rule{{Name: "gpt", PathGlob: "**/tag/js/gpt.js", Response: Response{Body: "ok"}}}, t.TempDir())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://ads.test/pagead/managed/js/tag/js/gpt.js", nil)
	if _, ok := engine.Match(request); !ok {
		t.Fatal("deep path did not match **/tag/js/gpt.js")
	}
}
