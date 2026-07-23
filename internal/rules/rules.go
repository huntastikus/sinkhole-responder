package rules

import (
	"encoding/base64"
	"fmt"
	"io"
	"maps"
	"net/textproto"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/huntastikus/sinkhole-responder/internal/assets"
	"golang.org/x/net/http/httpguts"
)

const maxBodyFileSize = 1 << 20

type Rule struct {
	Name         string            `yaml:"name"`
	Host         string            `yaml:"host"`
	HostGlob     string            `yaml:"host_glob"`
	PathGlob     string            `yaml:"path_glob"`
	PathRegex    string            `yaml:"path_regex"`
	Method       string            `yaml:"method"`
	SecFetchDest string            `yaml:"sec_fetch_dest"`
	Accept       string            `yaml:"accept"`
	Query        map[string]string `yaml:"query"`
	Headers      map[string]string `yaml:"headers"`
	Response     Response          `yaml:"response"`
}

type Response struct {
	Status      int               `yaml:"status"`
	ContentType string            `yaml:"content_type"`
	Body        string            `yaml:"body"`
	BodyBase64  string            `yaml:"body_base64"`
	BodyFile    string            `yaml:"body_file"`
	Headers     map[string]string `yaml:"headers"`
	DelayMS     int               `yaml:"delay_ms"`
	Embedded    string            `yaml:"embedded"`
}

// Compile validates rules and resolves all response bodies into memory.
func Compile(rs []Rule, configDir string) (*Engine, error) {
	engine := &Engine{rules: make([]compiledRule, 0, len(rs))}
	for i, rule := range rs {
		compiled, err := compileRule(rule, configDir)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ruleLabel(i, rule.Name), err)
		}
		if compiled.host != "" || compiled.hostGlob != "" {
			engine.hasHost = true
		}
		if len(compiled.query) > 0 {
			engine.hasQuery = true
		}
		engine.rules = append(engine.rules, compiled)
	}
	return engine, nil
}

func compileRule(rule Rule, configDir string) (compiledRule, error) {
	if !hasMatchCriterion(rule) {
		return compiledRule{}, fmt.Errorf("at least one match criterion is required")
	}

	if rule.Response.Status != 0 && (rule.Response.Status < 100 || rule.Response.Status > 599) {
		return compiledRule{}, fmt.Errorf("response status must be between 100 and 599, got %d", rule.Response.Status)
	}
	if rule.Response.DelayMS < 0 || rule.Response.DelayMS > 10000 {
		return compiledRule{}, fmt.Errorf("response delay_ms must be between 0 and 10000, got %d", rule.Response.DelayMS)
	}
	responseHeaders, err := compileResponseHeaders(rule.Response.Headers)
	if err != nil {
		return compiledRule{}, err
	}

	compiled := compiledRule{
		result: Compiled{
			Name:        rule.Name,
			Status:      rule.Response.Status,
			ContentType: rule.Response.ContentType,
			Headers:     responseHeaders,
			Delay:       time.Duration(rule.Response.DelayMS) * time.Millisecond,
		},
		hostGlob:     rule.HostGlob,
		pathGlob:     rule.PathGlob,
		method:       strings.ToUpper(rule.Method),
		secFetchDest: rule.SecFetchDest,
		accept:       strings.ToLower(rule.Accept),
		query:        maps.Clone(rule.Query),
		headers:      compileHeaders(rule.Headers),
	}

	if rule.Host != "" {
		compiled.host = normalizeHost(rule.Host)
		if compiled.host == "" {
			return compiledRule{}, fmt.Errorf("host is empty after normalization")
		}
	}
	if rule.HostGlob != "" {
		if err := validateGlob(rule.HostGlob); err != nil {
			return compiledRule{}, fmt.Errorf("invalid host_glob %q: %w", rule.HostGlob, err)
		}
	}
	if rule.PathGlob != "" {
		if err := validateGlob(rule.PathGlob); err != nil {
			return compiledRule{}, fmt.Errorf("invalid path_glob %q: %w", rule.PathGlob, err)
		}
	}
	if rule.PathRegex != "" {
		pathRegex, err := regexp.Compile(rule.PathRegex)
		if err != nil {
			return compiledRule{}, fmt.Errorf("invalid path_regex %q: %w", rule.PathRegex, err)
		}
		compiled.pathRegex = pathRegex
	}
	if rule.Method != "" && !validMethod(compiled.method) {
		return compiledRule{}, fmt.Errorf("unsupported method %q", rule.Method)
	}

	body, hasBody, contentType, err := compileBody(rule.Response, configDir)
	if err != nil {
		return compiledRule{}, err
	}
	compiled.result.Body = body
	compiled.result.HasBody = hasBody
	if compiled.result.ContentType == "" {
		compiled.result.ContentType = contentType
	}

	return compiled, nil
}

// validateGlob reports whether every non-"**" segment of pattern is a valid
// path.Match pattern. path.Match alone can miss a bad segment that sits after
// a segment which already failed to match, so each segment is checked.
func validateGlob(pattern string) error {
	for _, segment := range strings.Split(pattern, "/") {
		if segment == "**" {
			continue
		}
		if _, err := path.Match(segment, "x"); err != nil {
			return err
		}
	}
	return nil
}

func compileBody(response Response, configDir string) ([]byte, bool, string, error) {
	sources := 0
	for _, source := range []string{response.Body, response.BodyBase64, response.BodyFile, response.Embedded} {
		if source != "" {
			sources++
		}
	}
	if sources > 1 {
		return nil, false, "", fmt.Errorf("at most one response body source may be set")
	}

	// An empty body string is indistinguishable from an omitted YAML field. HasBody
	// is therefore true only for non-empty body fields or a named file/asset.
	switch {
	case response.Body != "":
		return []byte(response.Body), true, "", nil
	case response.BodyBase64 != "":
		body, err := base64.StdEncoding.DecodeString(response.BodyBase64)
		if err != nil {
			return nil, false, "", fmt.Errorf("decode response body_base64: %w", err)
		}
		return body, true, "", nil
	case response.BodyFile != "":
		body, err := readBodyFile(configDir, response.BodyFile)
		if err != nil {
			return nil, false, "", err
		}
		return body, true, "", nil
	case response.Embedded != "":
		asset, ok := assets.Get(response.Embedded)
		if !ok {
			return nil, false, "", fmt.Errorf("unknown embedded asset %q", response.Embedded)
		}
		return append([]byte(nil), asset.Body...), true, asset.ContentType, nil
	default:
		return nil, false, "", nil
	}
}

func readBodyFile(configDir, name string) ([]byte, error) {
	if filepath.IsAbs(name) {
		return nil, fmt.Errorf("response body_file %q escapes config directory", name)
	}

	base, err := filepath.Abs(configDir)
	if err != nil {
		return nil, fmt.Errorf("resolve config directory: %w", err)
	}
	target, err := filepath.Abs(filepath.Join(base, name))
	if err != nil {
		return nil, fmt.Errorf("resolve response body_file %q: %w", name, err)
	}
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return nil, fmt.Errorf("resolve response body_file %q relative to config directory: %w", name, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("response body_file %q escapes config directory", name)
	}

	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return nil, fmt.Errorf("resolve config directory symlinks: %w", err)
	}
	resolvedTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("resolve response body_file %q symlinks: %w", name, err)
		}
	} else {
		resolvedRel, err := filepath.Rel(resolvedBase, resolvedTarget)
		if err != nil {
			return nil, fmt.Errorf("resolve response body_file %q relative to config directory: %w", name, err)
		}
		if resolvedRel == ".." || strings.HasPrefix(resolvedRel, ".."+string(filepath.Separator)) || filepath.IsAbs(resolvedRel) {
			return nil, fmt.Errorf("response body_file %q escapes config directory", name)
		}
	}

	file, err := os.Open(target)
	if err != nil {
		return nil, fmt.Errorf("open response body_file %q: %w", name, err)
	}
	defer file.Close()

	body, err := io.ReadAll(io.LimitReader(file, maxBodyFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read response body_file %q: %w", name, err)
	}
	if len(body) > maxBodyFileSize {
		return nil, fmt.Errorf("response body_file %q exceeds 1 MiB", name)
	}
	return body, nil
}

func hasMatchCriterion(rule Rule) bool {
	return rule.Host != "" || rule.HostGlob != "" || rule.PathGlob != "" || rule.PathRegex != "" ||
		rule.Method != "" || rule.SecFetchDest != "" || rule.Accept != "" || len(rule.Query) > 0 || len(rule.Headers) > 0
}

func validMethod(method string) bool {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		return true
	default:
		return false
	}
}

func compileHeaders(headers map[string]string) []headerCriterion {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	criteria := make([]headerCriterion, 0, len(keys))
	for _, key := range keys {
		criteria = append(criteria, headerCriterion{name: textproto.CanonicalMIMEHeaderKey(key), value: headers[key]})
	}
	return criteria
}

func compileResponseHeaders(headers map[string]string) (map[string]string, error) {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	compiled := make(map[string]string, len(keys))
	for _, key := range keys {
		value := headers[key]
		if !httpguts.ValidHeaderFieldName(key) {
			return nil, fmt.Errorf("response header %q has an invalid field name", key)
		}
		if !httpguts.ValidHeaderFieldValue(value) {
			return nil, fmt.Errorf("response header %q has an invalid field value", key)
		}
		switch {
		case strings.EqualFold(key, "Content-Length"),
			strings.EqualFold(key, "Transfer-Encoding"),
			strings.EqualFold(key, "Connection"):
			return nil, fmt.Errorf("response header %q is not allowed", key)
		case strings.EqualFold(key, "Set-Cookie"):
			continue
		}
		compiled[textproto.CanonicalMIMEHeaderKey(key)] = value
	}
	if len(compiled) == 0 {
		return nil, nil
	}
	return compiled, nil
}

func ruleLabel(index int, name string) string {
	if name == "" {
		return fmt.Sprintf("rule %d", index)
	}
	return fmt.Sprintf("rule %d (%q)", index, name)
}
