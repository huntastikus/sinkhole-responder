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
		if !globMatch(rule.hostGlob, host) {
			return false
		}
	}

	requestPath := ""
	if r.URL != nil {
		requestPath = r.URL.Path
	}
	if rule.pathGlob != "" {
		if !globMatch(rule.pathGlob, requestPath) {
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

// globMatch matches name against pattern using path.Match semantics, extended
// so a standalone "**" segment matches zero or more path segments. A "**"
// embedded inside a segment (for example "a**b") is not special and keeps
// plain path.Match behavior.
func globMatch(pattern, name string) bool {
	if !hasDoublestarSegment(pattern) {
		matched, _ := path.Match(pattern, name)
		return matched
	}
	return matchSegments(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func hasDoublestarSegment(pattern string) bool {
	for _, segment := range strings.Split(pattern, "/") {
		if segment == "**" {
			return true
		}
	}
	return false
}

func matchSegments(pattern, name []string) bool {
	if len(pattern) == 0 {
		return len(name) == 0
	}
	if pattern[0] == "**" {
		for skip := 0; skip <= len(name); skip++ {
			if matchSegments(pattern[1:], name[skip:]) {
				return true
			}
		}
		return false
	}
	if len(name) == 0 {
		return false
	}
	matched, err := path.Match(pattern[0], name[0])
	if err != nil || !matched {
		return false
	}
	return matchSegments(pattern[1:], name[1:])
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
