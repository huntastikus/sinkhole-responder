// Package assets provides the embedded placeholder response bodies.
// Fonts are intentionally not embedded because a valid minimal font requires
// dependencies; font requests are handled with an HTTP 204 response instead.
package assets

import (
	"embed"
	"encoding/base64"
	"io/fs"
	"sort"
	"strings"
)

// Asset is an embedded response body and its media type.
type Asset struct {
	Body        []byte
	ContentType string
}

var (
	transparentGIF = []byte{
		'G', 'I', 'F', '8', '9', 'a',
		0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,
		0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
		0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
		0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
	}
	transparentPNG = mustDecodeBase64("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGNgAAIAAAUAAXpeqz8AAAAASUVORK5CYII=")
	transparentSVG = []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>`)
	emptyJS        = []byte("/* sinkhole */\n")
	emptyCSS       = []byte("/* sinkhole */\n")
	emptyJSON      = []byte("{}")
	blankHTML      = []byte(`<!doctype html><html><head><meta charset="utf-8"><title></title></head><body></body></html>`)
	emptyText      = []byte{}
	silentWAV      = []byte{
		'R', 'I', 'F', 'F', 0x24, 0x00, 0x00, 0x00, 'W', 'A', 'V', 'E',
		'f', 'm', 't', ' ', 0x10, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x01, 0x00, 0x40, 0x1f, 0x00, 0x00,
		0x40, 0x1f, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00,
		'd', 'a', 't', 'a', 0x00, 0x00, 0x00, 0x00,
	}
	minimalMP4 = mustDecodeBase64("AAAAGGZ0eXBpc29tAAACAGlzb21pc28yAAAAdG1vb3YAAABsbXZoZAAAAAAAAAAAAAAAAAAAA+gAAAAAAAEAAAEAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=")
)

var embedded = map[string]Asset{
	"blank-html":      {Body: blankHTML, ContentType: "text/html; charset=utf-8"},
	"empty-css":       {Body: emptyCSS, ContentType: "text/css"},
	"empty-js":        {Body: emptyJS, ContentType: "application/javascript"},
	"empty-json":      {Body: emptyJSON, ContentType: "application/json"},
	"empty-text":      {Body: emptyText, ContentType: "text/plain; charset=utf-8"},
	"minimal-mp4":     {Body: minimalMP4, ContentType: "video/mp4"},
	"silent-wav":      {Body: silentWAV, ContentType: "audio/wav"},
	"transparent-gif": {Body: transparentGIF, ContentType: "image/gif"},
	"transparent-png": {Body: transparentPNG, ContentType: "image/png"},
	"transparent-svg": {Body: transparentSVG, ContentType: "image/svg+xml"},
}

//go:embed stubs/*.js
var stubFiles embed.FS

func init() {
	entries, err := fs.ReadDir(stubFiles, "stubs")
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		body, err := fs.ReadFile(stubFiles, "stubs/"+entry.Name())
		if err != nil {
			panic(err)
		}
		name := strings.TrimSuffix(entry.Name(), ".js")
		embedded[name] = Asset{Body: body, ContentType: "application/javascript"}
	}
}

// Get returns the named embedded asset.
func Get(name string) (Asset, bool) {
	asset, ok := embedded[name]
	return asset, ok
}

// Names returns all known asset names in sorted order.
func Names() []string {
	names := make([]string, 0, len(embedded))
	for name := range embedded {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func mustDecodeBase64(encoded string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		panic(err)
	}
	return decoded
}
