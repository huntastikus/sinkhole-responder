package respond

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/huntastikus/sinkhole-responder/internal/config"
)

var fuzzJSONPCallbackPattern = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*$`)

func FuzzSelect(f *testing.F) {
	for _, input := range [][]byte{
		[]byte("example.test\x00api.json\x00application/json\x00\x00callback"),
		[]byte("example.test\x00api.json\x00application/json\x00\x00alert(1)"),
		[]byte("example.test\x00api.json\x00application/json\x00\x00a.b.c"),
		[]byte("example.test\x00api.json\x00application/json\x00\x00cb\n"),
		[]byte("example.test\x00api.json\x00application/json\x00\x00" + strings.Repeat("a", 200)),
		[]byte("example.test\x00api.json\x00application/json\x00\x00könyv"),
		[]byte("example.test\x00path%00.js\x00\x00\x00callback"),
		[]byte("example.test\x00asset\x00image/*, text/html\x00\x00callback"),
		[]byte("example.test\x00asset\x00\x00script\x00callback"),
	} {
		f.Add(input)
	}

	cfg := &config.Config{
		Defaults: config.DefaultsConfig{
			Status:        http.StatusOK,
			BeaconStatus:  http.StatusOK,
			MediaResponse: "204",
			CacheControl:  "no-store",
		},
		JSONP: config.JSONPConfig{Enabled: true, Param: "callback"},
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		fields := bytes.SplitN(input, []byte{0}, 5)
		for len(fields) < 5 {
			fields = append(fields, nil)
		}

		request := httptest.NewRequest(http.MethodGet, "http://placeholder.test/", nil)
		request.Host = string(fields[0])
		request.URL = &url.URL{
			Path: string(fields[1]),
			RawQuery: url.Values{
				cfg.JSONP.Param: []string{string(fields[4])},
			}.Encode(),
		}
		request.Header.Set("Accept", string(fields[2]))
		request.Header.Set("Sec-Fetch-Dest", string(fields[3]))

		decision := Select(request, nil, cfg)
		recorder := httptest.NewRecorder()
		Write(recorder, request, decision, cfg)

		const suffix = "({});"
		body := recorder.Body.String()
		if decision.ContentType != "application/javascript" || !strings.HasSuffix(body, suffix) {
			return
		}
		callback := strings.TrimSuffix(body, suffix)
		if len(callback) > 128 || !fuzzJSONPCallbackPattern.MatchString(callback) {
			t.Fatalf("invalid JSONP callback reached output: %q", callback)
		}
	})
}
