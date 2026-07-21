// Package respond selects and writes placeholder HTTP responses.
package respond

import (
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/assets"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/config"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/rules"
)

// Kind identifies the resource class selected for a request.
type Kind string

const (
	KindImage    Kind = "image"
	KindSVG      Kind = "svg"
	KindScript   Kind = "script"
	KindStyle    Kind = "style"
	KindJSON     Kind = "json"
	KindDocument Kind = "document"
	KindText     Kind = "text"
	KindAudio    Kind = "audio"
	KindVideo    Kind = "video"
	KindFont     Kind = "font"
	KindBeacon   Kind = "beacon"
)

// Decision is the response selected for a request. Body and ExtraHeaders are
// read-only views and may refer to data shared by multiple requests.
type Decision struct {
	RuleName     string
	Kind         Kind
	Status       int
	ContentType  string
	Body         []byte
	ExtraHeaders map[string]string
	Delay        time.Duration
}

var jsonpCallbackPattern = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*$`)

const maxJSONPCallbackLength = 128

// Select applies the configured rules followed by request resource hints.
func Select(r *http.Request, eng *rules.Engine, cfg *config.Config) Decision {
	generic := selectGeneric(r, cfg)

	if eng != nil {
		if matched, ok := eng.Match(r); ok {
			decision := generic
			decision.RuleName = matched.Name
			decision.ExtraHeaders = matched.Headers
			decision.Delay = matched.Delay
			if matched.Status != 0 {
				decision.Status = matched.Status
			}
			if matched.HasBody {
				decision.Body = matched.Body
			}
			if matched.ContentType != "" {
				decision.ContentType = matched.ContentType
			}
			// A rule body without an explicit media type inherits the generic
			// kind's type. This keeps custom bodies useful while avoiding an
			// unhelpful application/octet-stream default.
			return withoutForbiddenBody(decision)
		}
	}

	return applyJSONP(r, generic, cfg)
}

func selectGeneric(r *http.Request, cfg *config.Config) Decision {
	kind, imageAsset := selectKind(r)
	status := defaultStatus(cfg)
	if kind == KindBeacon {
		status = beaconStatus(cfg)
	}

	decision := Decision{Kind: kind, Status: status}
	assetName := ""
	switch kind {
	case KindImage:
		assetName = imageAsset
	case KindSVG:
		assetName = "transparent-svg"
	case KindScript:
		assetName = "empty-js"
	case KindStyle:
		assetName = "empty-css"
	case KindJSON:
		assetName = "empty-json"
	case KindDocument:
		assetName = "blank-html"
	case KindText, KindBeacon:
		assetName = "empty-text"
	case KindAudio:
		if mediaResponse(cfg) == "asset" {
			assetName = "silent-wav"
		} else {
			decision.Status = http.StatusNoContent
		}
	case KindVideo:
		if mediaResponse(cfg) == "asset" {
			assetName = "minimal-mp4"
		} else {
			decision.Status = http.StatusNoContent
		}
	case KindFont:
		// There is no dependency-free valid minimal font, so fonts always
		// receive a bodyless success response.
		decision.Status = http.StatusNoContent
	}

	if assetName != "" {
		asset, ok := assets.Get(assetName)
		if ok {
			decision.Body = asset.Body
			decision.ContentType = asset.ContentType
		}
	}
	return withoutForbiddenBody(decision)
}

func selectKind(r *http.Request) (Kind, string) {
	if r != nil {
		switch strings.ToLower(r.Header.Get("Sec-Fetch-Dest")) {
		case "image":
			return KindImage, "transparent-gif"
		case "script", "worker", "sharedworker", "serviceworker", "audioworklet", "paintworklet":
			return KindScript, ""
		case "style":
			return KindStyle, ""
		case "document", "iframe", "frame", "embed", "object":
			return KindDocument, ""
		case "font":
			return KindFont, ""
		case "audio":
			return KindAudio, ""
		case "track":
			return KindText, ""
		case "video":
			return KindVideo, ""
		case "manifest", "report":
			return KindJSON, ""
		}

		accept := strings.ToLower(r.Header.Get("Accept"))
		switch {
		case strings.Contains(accept, "text/html"):
			return KindDocument, ""
		case strings.Contains(accept, "image/svg+xml"):
			return KindSVG, ""
		case strings.Contains(accept, "image/"):
			return KindImage, "transparent-gif"
		case strings.Contains(accept, "text/css"):
			return KindStyle, ""
		case strings.Contains(accept, "application/json"):
			return KindJSON, ""
		case strings.Contains(accept, "javascript"):
			return KindScript, ""
		}

		requestPath := ""
		if r.URL != nil {
			requestPath = r.URL.Path
		}
		switch strings.ToLower(path.Ext(requestPath)) {
		case ".js", ".mjs":
			return KindScript, ""
		case ".css":
			return KindStyle, ""
		case ".json":
			return KindJSON, ""
		case ".svg":
			return KindSVG, ""
		case ".gif":
			return KindImage, "transparent-gif"
		case ".png", ".jpg", ".jpeg", ".webp", ".avif":
			return KindImage, "transparent-png"
		case ".html", ".htm":
			return KindDocument, ""
		case ".txt":
			return KindText, ""
		case ".mp3", ".wav", ".m4a", ".ogg", ".oga":
			return KindAudio, ""
		case ".mp4", ".webm", ".mov", ".m4v":
			return KindVideo, ""
		case ".woff", ".woff2", ".ttf", ".otf", ".eot":
			return KindFont, ""
		}
	}

	return KindBeacon, ""
}

func applyJSONP(r *http.Request, decision Decision, cfg *config.Config) Decision {
	if cfg == nil || !cfg.JSONP.Enabled || r == nil || r.URL == nil {
		return decision
	}
	if decision.Kind != KindScript && decision.Kind != KindJSON && decision.Kind != KindBeacon {
		return decision
	}

	values, present := r.URL.Query()[cfg.JSONP.Param]
	if !present || len(values) == 0 {
		return decision
	}
	callback := values[0]
	if len(callback) > maxJSONPCallbackLength || !jsonpCallbackPattern.MatchString(callback) {
		return decision
	}

	decision.Status = http.StatusOK
	decision.ContentType = "application/javascript"
	decision.Body = []byte(callback + "({});")
	return decision
}

func withoutForbiddenBody(decision Decision) Decision {
	if decision.Status == http.StatusNoContent || decision.Status == http.StatusNotModified {
		decision.Body = nil
		decision.ContentType = ""
	}
	return decision
}

func defaultStatus(cfg *config.Config) int {
	if cfg == nil {
		return http.StatusOK
	}
	return cfg.Defaults.Status
}

func beaconStatus(cfg *config.Config) int {
	if cfg == nil {
		return http.StatusOK
	}
	return cfg.Defaults.BeaconStatus
}

func mediaResponse(cfg *config.Config) string {
	if cfg == nil {
		return "204"
	}
	return cfg.Defaults.MediaResponse
}
