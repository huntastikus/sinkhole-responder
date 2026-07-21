package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/huntastikus/sinkhole-responder/internal/config"
)

const redactedValue = "[REDACTED]"

type postBodyKind uint8

const (
	postBodyText postBodyKind = iota
	postBodyJSON
	postBodyForm
)

type postBodyLog struct {
	value     string
	omitted   string
	truncated bool
	redacted  bool
}

type boundedBodyCapture struct {
	bytes     []byte
	limit     int
	truncated bool
	kind      postBodyKind
}

func (c *boundedBodyCapture) Write(data []byte) (int, error) {
	written := len(data)
	remaining := c.limit - len(c.bytes)
	if remaining <= 0 {
		c.truncated = c.truncated || len(data) > 0
		return written, nil
	}
	if len(data) > remaining {
		c.bytes = append(c.bytes, data[:remaining]...)
		c.truncated = true
		return written, nil
	}
	c.bytes = append(c.bytes, data...)
	return written, nil
}

func preparePostBodyCapture(cfg *config.Config, r *http.Request) (*boundedBodyCapture, *postBodyLog) {
	if cfg == nil || !cfg.Logging.LogPostBody || (cfg.Logging.AccessLog != nil && !*cfg.Logging.AccessLog) {
		return nil, nil
	}
	if encoding := strings.TrimSpace(r.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return nil, &postBodyLog{omitted: "encoded body"}
	}

	kind, reason := classifyPostBody(r.Header.Get("Content-Type"))
	if reason != "" {
		return nil, &postBodyLog{omitted: reason}
	}
	limit := cfg.Logging.PostBodyLogMaxBytes
	if limit < 1 {
		limit = config.DefaultPostBodyLogMaxBytes
	}
	return &boundedBodyCapture{limit: int(limit), kind: kind}, nil
}

func classifyPostBody(contentType string) (postBodyKind, string) {
	if strings.TrimSpace(contentType) == "" {
		return postBodyText, ""
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return 0, "invalid content type"
	}
	mediaType = strings.ToLower(mediaType)
	switch {
	case mediaType == "application/json", strings.HasSuffix(mediaType, "+json"):
		return postBodyJSON, ""
	case mediaType == "application/x-www-form-urlencoded":
		return postBodyForm, ""
	case strings.HasPrefix(mediaType, "text/"):
		return postBodyText, ""
	case strings.HasPrefix(mediaType, "multipart/"):
		return 0, "multipart body"
	default:
		return 0, "unsupported content type"
	}
}

func (c *boundedBodyCapture) finish() *postBodyLog {
	data := c.bytes
	if !utf8.Valid(data) && c.truncated {
		for removed := 0; removed < utf8.UTFMax-1 && len(data) > 0 && !utf8.Valid(data); removed++ {
			data = data[:len(data)-1]
		}
	}
	if !utf8.Valid(data) {
		return &postBodyLog{omitted: "non-UTF-8 body", truncated: c.truncated}
	}

	result := &postBodyLog{value: string(data), truncated: c.truncated}
	switch c.kind {
	case postBodyJSON:
		if c.truncated {
			return &postBodyLog{omitted: "truncated JSON body", truncated: true}
		}
		value, redacted, ok := redactJSON(data)
		if !ok {
			return &postBodyLog{omitted: "invalid JSON body"}
		}
		result.value = value
		result.redacted = redacted
	case postBodyForm:
		value, redacted, err := redactForm(string(data))
		if err != nil {
			return &postBodyLog{omitted: "invalid form body", truncated: c.truncated}
		}
		result.value = value
		result.redacted = redacted
	}
	return result
}

func redactJSON(data []byte) (string, bool, bool) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", false, false
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return "", false, false
	}
	redacted := redactJSONValue(value)
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", false, false
	}
	return string(encoded), redacted, true
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

func redactJSONValue(value any) bool {
	redacted := false
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if sensitiveField(key) {
				typed[key] = redactedValue
				redacted = true
				continue
			}
			redacted = redactJSONValue(child) || redacted
		}
	case []any:
		for _, child := range typed {
			redacted = redactJSONValue(child) || redacted
		}
	}
	return redacted
}

func redactForm(body string) (string, bool, error) {
	values, err := url.ParseQuery(body)
	if err != nil {
		return "", false, err
	}
	redacted := false
	for key := range values {
		if sensitiveField(key) {
			values[key] = []string{redactedValue}
			redacted = true
		}
	}
	return values.Encode(), redacted, nil
}

func sensitiveField(name string) bool {
	normalized := strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(strings.ToLower(name))
	compact := strings.ReplaceAll(normalized, "_", "")
	for _, marker := range []string{
		"password", "passwd", "secret", "token", "authorization", "cookie", "session", "credential", "apikey", "privatekey",
	} {
		if strings.Contains(compact, marker) {
			return true
		}
	}
	for _, part := range strings.Split(normalized, "_") {
		switch part {
		case "auth", "bearer", "jwt":
			return true
		}
	}
	return false
}
