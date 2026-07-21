package rules

import (
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

type Engine struct {
	rules    []compiledRule
	hasHost  bool
	hasQuery bool
}

type Compiled struct {
	Name        string
	Status      int
	ContentType string
	Body        []byte
	HasBody     bool
	Headers     map[string]string
	Delay       time.Duration
}

type compiledRule struct {
	result       Compiled
	host         string
	hostGlob     string
	pathGlob     string
	pathRegex    *regexp.Regexp
	method       string
	secFetchDest string
	accept       string
	query        map[string]string
	headers      []headerCriterion
}

type headerCriterion struct {
	name  string
	value string
}

// Len reports the number of compiled rules.
func (e *Engine) Len() int {
	if e == nil {
		return 0
	}
	return len(e.rules)
}

// Match returns the first rule whose configured criteria all match the request.
func (e *Engine) Match(r *http.Request) (*Compiled, bool) {
	if e == nil || r == nil {
		return nil, false
	}

	var host string
	if e.hasHost {
		host = normalizeHost(r.Host)
	}
	var query url.Values
	if e.hasQuery && r.URL != nil {
		query = r.URL.Query()
	}
	for i := range e.rules {
		if e.rules[i].matches(r, host, query) {
			return &e.rules[i].result, true
		}
	}
	return nil, false
}

func (rule *compiledRule) matches(r *http.Request, host string, query url.Values) bool {
	if rule.host != "" && host != rule.host {
		return false
	}
	// Host glob patterns are matched against the normalized ASCII/punycode host;
	// pattern authors should write punycode or ASCII globs.
	if rule.hostGlob != "" {
		matched, _ := path.Match(rule.hostGlob, host)
		if !matched {
			return false
		}
	}

	requestPath := ""
	if r.URL != nil {
		requestPath = r.URL.Path
	}
	if rule.pathGlob != "" {
		matched, _ := path.Match(rule.pathGlob, requestPath)
		if !matched {
			return false
		}
	}
	if rule.pathRegex != nil && !rule.pathRegex.MatchString(requestPath) {
		return false
	}
	if rule.method != "" && strings.ToUpper(r.Method) != rule.method {
		return false
	}
	if rule.secFetchDest != "" && !strings.EqualFold(r.Header.Get("Sec-Fetch-Dest"), rule.secFetchDest) {
		return false
	}
	if rule.accept != "" && !strings.Contains(strings.ToLower(r.Header.Get("Accept")), rule.accept) {
		return false
	}
	for key, expected := range rule.query {
		values, present := query[key]
		if !present || (expected != "" && (len(values) == 0 || values[0] != expected)) {
			return false
		}
	}
	for _, criterion := range rule.headers {
		values, present := r.Header[criterion.name]
		if !present || (criterion.value != "" && (len(values) == 0 || values[0] != criterion.value)) {
			return false
		}
	}
	return true
}

func normalizeHost(raw string) string {
	host := raw
	if splitHost, _, err := net.SplitHostPort(raw); err == nil {
		host = splitHost
	} else if len(raw) >= 2 && raw[0] == '[' && raw[len(raw)-1] == ']' {
		host = raw[1 : len(raw)-1]
	}
	host = strings.TrimSuffix(host, ".")
	host = strings.ToLower(host)
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return host
	}
	return ascii
}
