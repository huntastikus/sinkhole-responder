package respond

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/config"
	"github.com/huntastikus/sinkhole-responder/internal/rules"
)

func TestSelectPriority(t *testing.T) {
	cfg := testConfig()
	ruleEngine := compileRules(t, []rules.Rule{{
		Name:     "override",
		PathGlob: "/*",
		Response: rules.Response{Status: http.StatusForbidden, ContentType: "text/custom", Body: "rule"},
	}})

	tests := []struct {
		name       string
		url        string
		headers    map[string]string
		engine     *rules.Engine
		wantKind   Kind
		wantStatus int
		wantType   string
		wantBody   string
		wantRule   string
	}{
		{
			name:       "rule beats fetch destination response",
			url:        "http://example.test/x",
			headers:    map[string]string{"Sec-Fetch-Dest": "image"},
			engine:     ruleEngine,
			wantKind:   KindImage,
			wantStatus: http.StatusForbidden,
			wantType:   "text/custom",
			wantBody:   "rule",
			wantRule:   "override",
		},
		{
			name:       "fetch destination beats accept",
			url:        "http://example.test/x",
			headers:    map[string]string{"Sec-Fetch-Dest": "image", "Accept": "text/html"},
			wantKind:   KindImage,
			wantStatus: http.StatusOK,
			wantType:   "image/gif",
		},
		{
			name:       "accept beats extension",
			url:        "http://example.test/x.js",
			headers:    map[string]string{"Accept": "text/css"},
			wantKind:   KindStyle,
			wantStatus: http.StatusOK,
			wantType:   "text/css",
		},
		{
			name:       "extension beats fallback",
			url:        "http://example.test/x.json",
			wantKind:   KindJSON,
			wantStatus: http.StatusOK,
			wantType:   "application/json",
		},
		{
			name:       "empty fetch destination falls through",
			url:        "http://example.test/x.js",
			headers:    map[string]string{"Sec-Fetch-Dest": "EMPTY", "Accept": "text/html"},
			wantKind:   KindDocument,
			wantStatus: http.StatusOK,
			wantType:   "text/html; charset=utf-8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Select(newRequest(t, http.MethodGet, tt.url, tt.headers), tt.engine, cfg)
			if d.Kind != tt.wantKind || d.Status != tt.wantStatus || d.ContentType != tt.wantType || d.RuleName != tt.wantRule {
				t.Fatalf("Select() = kind %q, status %d, type %q, rule %q; want %q, %d, %q, %q", d.Kind, d.Status, d.ContentType, d.RuleName, tt.wantKind, tt.wantStatus, tt.wantType, tt.wantRule)
			}
			if tt.wantBody != "" && string(d.Body) != tt.wantBody {
				t.Fatalf("Select().Body = %q, want %q", d.Body, tt.wantBody)
			}
		})
	}
}

func TestSelectSecFetchDestinations(t *testing.T) {
	tests := []struct {
		destination string
		want        Kind
	}{
		{destination: "image", want: KindImage},
		{destination: "script", want: KindScript},
		{destination: "worker", want: KindScript},
		{destination: "sharedworker", want: KindScript},
		{destination: "serviceworker", want: KindScript},
		{destination: "audioworklet", want: KindScript},
		{destination: "paintworklet", want: KindScript},
		{destination: "style", want: KindStyle},
		{destination: "document", want: KindDocument},
		{destination: "iframe", want: KindDocument},
		{destination: "frame", want: KindDocument},
		{destination: "embed", want: KindDocument},
		{destination: "object", want: KindDocument},
		{destination: "font", want: KindFont},
		{destination: "audio", want: KindAudio},
		{destination: "track", want: KindText},
		{destination: "video", want: KindVideo},
		{destination: "manifest", want: KindJSON},
		{destination: "report", want: KindJSON},
	}

	for _, tt := range tests {
		t.Run(tt.destination, func(t *testing.T) {
			r := newRequest(t, http.MethodGet, "http://example.test/file.unknown", map[string]string{
				"Sec-Fetch-Dest": strings.ToUpper(tt.destination),
			})
			if got := Select(r, nil, testConfig()).Kind; got != tt.want {
				t.Fatalf("Select().Kind = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSelectAccept(t *testing.T) {
	tests := []struct {
		accept   string
		wantKind Kind
		wantType string
	}{
		{accept: "TEXT/HTML", wantKind: KindDocument, wantType: "text/html; charset=utf-8"},
		{accept: "image/svg+xml", wantKind: KindSVG, wantType: "image/svg+xml"},
		{accept: "image/avif,image/webp", wantKind: KindImage, wantType: "image/gif"},
		{accept: "text/css,*/*;q=0.1", wantKind: KindStyle, wantType: "text/css"},
		{accept: "application/json", wantKind: KindJSON, wantType: "application/json"},
		{accept: "text/javascript", wantKind: KindScript, wantType: "application/javascript"},
	}

	for _, tt := range tests {
		t.Run(tt.accept, func(t *testing.T) {
			r := newRequest(t, http.MethodGet, "http://example.test/file.unknown", map[string]string{"Accept": tt.accept})
			d := Select(r, nil, testConfig())
			if d.Kind != tt.wantKind || d.ContentType != tt.wantType {
				t.Fatalf("Select() = kind %q, type %q; want %q, %q", d.Kind, d.ContentType, tt.wantKind, tt.wantType)
			}
		})
	}
}

func TestSelectExtensions(t *testing.T) {
	tests := []struct {
		path     string
		wantKind Kind
		wantType string
	}{
		{path: "/x.MJS", wantKind: KindScript, wantType: "application/javascript"},
		{path: "/x.css", wantKind: KindStyle, wantType: "text/css"},
		{path: "/x.json", wantKind: KindJSON, wantType: "application/json"},
		{path: "/x.svg", wantKind: KindSVG, wantType: "image/svg+xml"},
		{path: "/x.gif", wantKind: KindImage, wantType: "image/gif"},
		{path: "/x.png", wantKind: KindImage, wantType: "image/png"},
		{path: "/x.html", wantKind: KindDocument, wantType: "text/html; charset=utf-8"},
		{path: "/x.txt", wantKind: KindText, wantType: "text/plain; charset=utf-8"},
		{path: "/x.ogg", wantKind: KindAudio, wantType: "audio/wav"},
		{path: "/x.webm", wantKind: KindVideo, wantType: "video/mp4"},
		{path: "/x.woff2", wantKind: KindFont, wantType: ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			d := Select(newRequest(t, http.MethodGet, "http://example.test"+tt.path, nil), nil, testConfig())
			if d.Kind != tt.wantKind || d.ContentType != tt.wantType {
				t.Fatalf("Select() = kind %q, type %q; want %q, %q", d.Kind, d.ContentType, tt.wantKind, tt.wantType)
			}
		})
	}

	generic := Select(newRequest(t, http.MethodGet, "http://example.test/x", map[string]string{"Accept": "image/*"}), nil, testConfig())
	if generic.ContentType != "image/gif" {
		t.Fatalf("generic image ContentType = %q, want image/gif", generic.ContentType)
	}
}

func TestSelectFallbackBeacon(t *testing.T) {
	tests := []struct {
		status   int
		wantType string
	}{
		{status: http.StatusOK, wantType: "text/plain; charset=utf-8"},
		{status: http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			cfg := testConfig()
			cfg.Defaults.BeaconStatus = tt.status
			d := Select(newRequest(t, http.MethodGet, "http://example.test/unknown", nil), nil, cfg)
			if d.Kind != KindBeacon || d.Status != tt.status || d.ContentType != tt.wantType || len(d.Body) != 0 {
				t.Fatalf("Select() = kind %q, status %d, type %q, body len %d", d.Kind, d.Status, d.ContentType, len(d.Body))
			}
			recorder := httptest.NewRecorder()
			Write(recorder, newRequest(t, http.MethodGet, "http://example.test/unknown", nil), d, cfg)
			if tt.status == http.StatusNoContent && (recorder.Header().Get("Content-Type") != "" || recorder.Header().Get("Content-Length") != "") {
				t.Fatalf("204 headers include body metadata: %v", recorder.Header())
			}
		})
	}
}

func TestSelectMediaResponse(t *testing.T) {
	tests := []struct {
		mode       string
		path       string
		wantKind   Kind
		wantStatus int
		wantBody   bool
	}{
		{mode: "204", path: "/x.wav", wantKind: KindAudio, wantStatus: http.StatusNoContent},
		{mode: "asset", path: "/x.wav", wantKind: KindAudio, wantStatus: http.StatusOK, wantBody: true},
		{mode: "204", path: "/x.mp4", wantKind: KindVideo, wantStatus: http.StatusNoContent},
		{mode: "asset", path: "/x.mp4", wantKind: KindVideo, wantStatus: http.StatusOK, wantBody: true},
		{mode: "204", path: "/x.woff", wantKind: KindFont, wantStatus: http.StatusNoContent},
		{mode: "asset", path: "/x.woff", wantKind: KindFont, wantStatus: http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.mode+tt.path, func(t *testing.T) {
			cfg := testConfig()
			cfg.Defaults.MediaResponse = tt.mode
			d := Select(newRequest(t, http.MethodGet, "http://example.test"+tt.path, nil), nil, cfg)
			if d.Kind != tt.wantKind || d.Status != tt.wantStatus || (len(d.Body) > 0) != tt.wantBody {
				t.Fatalf("Select() = kind %q, status %d, body len %d; want %q, %d, body %v", d.Kind, d.Status, len(d.Body), tt.wantKind, tt.wantStatus, tt.wantBody)
			}
		})
	}
}

func TestSelectJSONP(t *testing.T) {
	longCallback := "a" + strings.Repeat("b", 128)
	tests := []struct {
		name       string
		enabled    bool
		callback   string
		wantBody   string
		wantType   string
		wantStatus int
	}{
		{name: "disabled", callback: "cb", wantBody: "{}", wantType: "application/json", wantStatus: http.StatusOK},
		{name: "valid", enabled: true, callback: "cb", wantBody: "cb({});", wantType: "application/javascript", wantStatus: http.StatusOK},
		{name: "dotted", enabled: true, callback: "a.b.c", wantBody: "a.b.c({});", wantType: "application/javascript", wantStatus: http.StatusOK},
		{name: "invalid expression", enabled: true, callback: "alert(1)", wantBody: "{}", wantType: "application/json", wantStatus: http.StatusOK},
		{name: "too long", enabled: true, callback: longCallback, wantBody: "{}", wantType: "application/json", wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.JSONP.Enabled = tt.enabled
			r := newRequest(t, http.MethodGet, "http://example.test/data.json?callback="+tt.callback, nil)
			d := Select(r, nil, cfg)
			if string(d.Body) != tt.wantBody || d.ContentType != tt.wantType || d.Status != tt.wantStatus {
				t.Fatalf("Select() = body %q, type %q, status %d; want %q, %q, %d", d.Body, d.ContentType, d.Status, tt.wantBody, tt.wantType, tt.wantStatus)
			}
		})
	}
}

func TestSelectRuleIsNeverJSONPWrappedAndInheritsGenericFields(t *testing.T) {
	cfg := testConfig()
	cfg.JSONP.Enabled = true
	engine := compileRules(t, []rules.Rule{{
		Name:     "plain-rule",
		PathGlob: "/*",
		Response: rules.Response{Body: "rule body"},
	}})
	d := Select(newRequest(t, http.MethodGet, "http://example.test/data.json?callback=cb", nil), engine, cfg)
	if d.RuleName != "plain-rule" || d.Kind != KindJSON || d.Status != http.StatusOK || d.ContentType != "application/json" || string(d.Body) != "rule body" {
		t.Fatalf("Select() = %+v, body %q", d, d.Body)
	}
}

func TestWriteHeadersAndCORS(t *testing.T) {
	tests := []struct {
		name       string
		origin     string
		wantOrigin string
		wantCreds  string
		wantVary   bool
	}{
		{name: "no origin", wantOrigin: "*"},
		{name: "echo origin", origin: "https://a.example", wantOrigin: "https://a.example", wantCreds: "true", wantVary: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			r := newRequest(t, http.MethodGet, "http://example.test/x.js", nil)
			if tt.origin != "" {
				r.Header.Set("Origin", tt.origin)
			}
			d := Select(r, nil, cfg)
			d.ExtraHeaders = map[string]string{"Set-Cookie": "forbidden=1"}
			recorder := httptest.NewRecorder()
			Write(recorder, r, d, cfg)

			header := recorder.Header()
			if recorder.Code != http.StatusOK || header.Get("Content-Type") != "application/javascript" || header.Get("Content-Length") != "15" {
				t.Fatalf("basic response = status %d, headers %v", recorder.Code, header)
			}
			if header.Get("Access-Control-Allow-Origin") != tt.wantOrigin || header.Get("Access-Control-Allow-Credentials") != tt.wantCreds {
				t.Fatalf("CORS headers = %v", header)
			}
			if got := varyContains(header, "Origin"); got != tt.wantVary {
				t.Fatalf("Vary contains Origin = %v, want %v; headers %v", got, tt.wantVary, header)
			}
			for key, want := range map[string]string{
				"Cross-Origin-Resource-Policy": "cross-origin",
				"Timing-Allow-Origin":          "*",
				"Cache-Control":                "no-store",
				"X-Sinkhole":                   "1",
			} {
				if got := header.Get(key); got != want {
					t.Errorf("%s = %q, want %q", key, got, want)
				}
			}
			if header.Get("Set-Cookie") != "" {
				t.Fatalf("Set-Cookie unexpectedly present: %q", header.Get("Set-Cookie"))
			}
		})
	}
}

func TestWriteRuleExtraHeadersOverrideDefaults(t *testing.T) {
	cfg := testConfig()
	engine := compileRules(t, []rules.Rule{{
		PathGlob: "/*",
		Response: rules.Response{Headers: map[string]string{"Cache-Control": "max-age=60"}},
	}})
	r := newRequest(t, http.MethodGet, "http://example.test/x.js", nil)
	recorder := httptest.NewRecorder()
	Write(recorder, r, Select(r, engine, cfg), cfg)
	if got := recorder.Header().Get("Cache-Control"); got != "max-age=60" {
		t.Fatalf("Cache-Control = %q, want max-age=60", got)
	}
}

func TestWriteHEADHasGETHeadersAndNoBody(t *testing.T) {
	cfg := testConfig()
	getRequest := newRequest(t, http.MethodGet, "http://example.test/x.png", nil)
	getRecorder := httptest.NewRecorder()
	Write(getRecorder, getRequest, Select(getRequest, nil, cfg), cfg)

	headRequest := newRequest(t, http.MethodHead, "http://example.test/x.png", nil)
	headRecorder := httptest.NewRecorder()
	Write(headRecorder, headRequest, Select(headRequest, nil, cfg), cfg)

	for _, key := range []string{"Content-Type", "Content-Length", "Access-Control-Allow-Origin", "Cross-Origin-Resource-Policy", "Timing-Allow-Origin", "Cache-Control", "X-Sinkhole"} {
		if got, want := headRecorder.Header().Get(key), getRecorder.Header().Get(key); got != want {
			t.Errorf("HEAD %s = %q, GET = %q", key, got, want)
		}
	}
	if headRecorder.Body.Len() != 0 {
		t.Fatalf("HEAD body len = %d, want 0", headRecorder.Body.Len())
	}
}

func TestWritePreflightViaWrite(t *testing.T) {
	r := newRequest(t, http.MethodOptions, "http://example.test/x", map[string]string{
		"Origin":                         "https://a.example",
		"Access-Control-Request-Method":  "POST",
		"Access-Control-Request-Headers": "x-custom",
	})
	recorder := httptest.NewRecorder()
	Write(recorder, r, Decision{Status: http.StatusOK, ContentType: "text/plain", Body: []byte("ignored")}, testConfig())

	header := recorder.Header()
	if recorder.Code != http.StatusNoContent || recorder.Body.Len() != 0 {
		t.Fatalf("preflight = status %d, body %q", recorder.Code, recorder.Body.Bytes())
	}
	for key, want := range map[string]string{
		"Access-Control-Allow-Origin":      "https://a.example",
		"Access-Control-Allow-Credentials": "true",
		"Access-Control-Allow-Methods":     allowedMethods,
		"Access-Control-Allow-Headers":     "x-custom",
		"Access-Control-Max-Age":           "86400",
	} {
		if got := header.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if !varyContains(header, "Origin") || header.Get("Content-Type") != "" || header.Get("Content-Length") != "" {
		t.Fatalf("preflight headers = %v", header)
	}
}

func TestWriteDelayAndCancellation(t *testing.T) {
	t.Run("waits for rule delay", func(t *testing.T) {
		engine := compileRules(t, []rules.Rule{{
			PathGlob: "/*",
			Response: rules.Response{DelayMS: 30},
		}})
		r := newRequest(t, http.MethodGet, "http://example.test/x.js", nil)
		start := time.Now()
		Write(httptest.NewRecorder(), r, Select(r, engine, testConfig()), testConfig())
		if elapsed := time.Since(start); elapsed < 30*time.Millisecond {
			t.Fatalf("Write() elapsed %v, want at least 30ms", elapsed)
		}
	})

	t.Run("canceled context returns early", func(t *testing.T) {
		base := newRequest(t, http.MethodGet, "http://example.test/x.js", nil)
		ctx, cancel := context.WithCancel(base.Context())
		r := base.WithContext(ctx)
		time.AfterFunc(50*time.Millisecond, cancel)
		start := time.Now()
		Write(httptest.NewRecorder(), r, Decision{Status: http.StatusOK, Delay: 2 * time.Second}, testConfig())
		if elapsed := time.Since(start); elapsed >= 500*time.Millisecond {
			t.Fatalf("Write() elapsed %v after cancellation, want under 500ms", elapsed)
		}
	})
}

func TestRuleResponseAndBodyRemainImmutable(t *testing.T) {
	engine := compileRules(t, []rules.Rule{{
		Name:     "blocked",
		PathGlob: "/*",
		Response: rules.Response{Status: http.StatusForbidden, ContentType: "application/custom", Body: "immutable"},
	}})
	r := newRequest(t, http.MethodGet, "http://example.test/x", nil)
	compiled, ok := engine.Match(r)
	if !ok {
		t.Fatal("rule did not match")
	}
	wantBody := append([]byte(nil), compiled.Body...)

	d := Select(r, engine, testConfig())
	if d.Status != http.StatusForbidden || d.ContentType != "application/custom" || string(d.Body) != "immutable" {
		t.Fatalf("Select() = status %d, type %q, body %q", d.Status, d.ContentType, d.Body)
	}
	recorder := httptest.NewRecorder()
	Write(recorder, r, d, testConfig())
	if recorder.Code != http.StatusForbidden || recorder.Body.String() != "immutable" {
		t.Fatalf("Write() = status %d, body %q", recorder.Code, recorder.Body.String())
	}
	if !bytes.Equal(compiled.Body, wantBody) {
		t.Fatalf("compiled body mutated: got %q, want %q", compiled.Body, wantBody)
	}
}

func TestSelectNilURLDoesNotPanic(t *testing.T) {
	r := &http.Request{Method: http.MethodGet, Header: make(http.Header)}
	d := Select(r, nil, testConfig())
	if d.Kind != KindBeacon {
		t.Fatalf("Select().Kind = %q, want beacon", d.Kind)
	}
}

func testConfig() *config.Config {
	return &config.Config{
		Defaults: config.DefaultsConfig{
			Status:        http.StatusOK,
			BeaconStatus:  http.StatusOK,
			MediaResponse: "asset",
			CacheControl:  "no-store",
		},
		JSONP: config.JSONPConfig{Param: "callback"},
	}
}

func compileRules(t *testing.T, configured []rules.Rule) *rules.Engine {
	t.Helper()
	engine, err := rules.Compile(configured, t.TempDir())
	if err != nil {
		t.Fatalf("rules.Compile: %v", err)
	}
	return engine
}

func newRequest(t *testing.T, method, target string, headers map[string]string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	return r
}

func varyContains(header http.Header, want string) bool {
	for _, value := range header.Values("Vary") {
		for _, field := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(field), want) {
				return true
			}
		}
	}
	return false
}
