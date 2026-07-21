package assets

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"image/gif"
	"image/png"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestTransparentGIF(t *testing.T) {
	asset, ok := Get("transparent-gif")
	if !ok {
		t.Fatal("Get(transparent-gif) returned ok=false")
	}

	decoded, err := gif.DecodeAll(bytes.NewReader(asset.Body))
	if err != nil {
		t.Fatalf("gif.DecodeAll() error = %v", err)
	}
	if len(decoded.Image) != 1 {
		t.Fatalf("frame count = %d, want 1", len(decoded.Image))
	}
	if bounds := decoded.Image[0].Bounds(); bounds.Dx() != 1 || bounds.Dy() != 1 {
		t.Fatalf("bounds = %v, want 1x1", bounds)
	}
	if _, _, _, alpha := decoded.Image[0].At(0, 0).RGBA(); alpha != 0 {
		t.Fatalf("pixel alpha = %d, want 0", alpha)
	}
}

func TestTransparentPNG(t *testing.T) {
	asset, ok := Get("transparent-png")
	if !ok {
		t.Fatal("Get(transparent-png) returned ok=false")
	}

	decoded, err := png.Decode(bytes.NewReader(asset.Body))
	if err != nil {
		t.Fatalf("png.Decode() error = %v", err)
	}
	if bounds := decoded.Bounds(); bounds.Dx() != 1 || bounds.Dy() != 1 {
		t.Fatalf("bounds = %v, want 1x1", bounds)
	}
	if _, _, _, alpha := decoded.At(0, 0).RGBA(); alpha != 0 {
		t.Fatalf("pixel alpha = %d, want 0", alpha)
	}
}

func TestTransparentSVG(t *testing.T) {
	asset, ok := Get("transparent-svg")
	if !ok {
		t.Fatal("Get(transparent-svg) returned ok=false")
	}

	var svg struct {
		XMLName xml.Name
		Width   string `xml:"width,attr"`
		Height  string `xml:"height,attr"`
	}
	if err := xml.Unmarshal(asset.Body, &svg); err != nil {
		t.Fatalf("xml.Unmarshal() error = %v", err)
	}
	if svg.XMLName.Local != "svg" || svg.XMLName.Space != "http://www.w3.org/2000/svg" {
		t.Errorf("root name = {%s}%s, want SVG namespace and name", svg.XMLName.Space, svg.XMLName.Local)
	}
	if svg.Width != "1" || svg.Height != "1" {
		t.Errorf("dimensions = %sx%s, want 1x1", svg.Width, svg.Height)
	}
}

func TestEmptyJSON(t *testing.T) {
	asset, ok := Get("empty-json")
	if !ok {
		t.Fatal("Get(empty-json) returned ok=false")
	}
	if !json.Valid(asset.Body) {
		t.Fatal("empty-json is not valid JSON")
	}

	var value map[string]any
	if err := json.Unmarshal(asset.Body, &value); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if len(value) != 0 {
		t.Fatalf("decoded JSON = %v, want empty object", value)
	}
}

func TestBlankHTML(t *testing.T) {
	asset, ok := Get("blank-html")
	if !ok {
		t.Fatal("Get(blank-html) returned ok=false")
	}
	lower := strings.ToLower(string(asset.Body))
	if !strings.HasPrefix(lower, "<!doctype html>") {
		t.Errorf("blank-html does not start with an HTML doctype: %q", asset.Body)
	}
	if !strings.Contains(lower, "charset=\"utf-8\"") {
		t.Errorf("blank-html does not declare charset=utf-8: %q", asset.Body)
	}
}

func TestSilentWAV(t *testing.T) {
	asset, ok := Get("silent-wav")
	if !ok {
		t.Fatal("Get(silent-wav) returned ok=false")
	}
	body := asset.Body
	if len(body) != 44 {
		t.Fatalf("length = %d, want 44", len(body))
	}
	if string(body[0:4]) != "RIFF" || string(body[8:12]) != "WAVE" {
		t.Fatalf("invalid RIFF/WAVE signature: %q ... %q", body[0:4], body[8:12])
	}
	if size := binary.LittleEndian.Uint32(body[4:8]); size != uint32(len(body)-8) {
		t.Fatalf("RIFF ChunkSize = %d, want %d", size, len(body)-8)
	}

	fmtFound := false
	dataFound := false
	for offset := 12; offset < len(body); {
		if offset+8 > len(body) {
			t.Fatalf("truncated chunk header at offset %d", offset)
		}
		chunkType := string(body[offset : offset+4])
		chunkSize := int(binary.LittleEndian.Uint32(body[offset+4 : offset+8]))
		dataStart := offset + 8
		dataEnd := dataStart + chunkSize
		if dataEnd > len(body) {
			t.Fatalf("%s chunk extends past body", chunkType)
		}
		switch chunkType {
		case "fmt ":
			fmtFound = true
			if chunkSize < 16 {
				t.Fatalf("fmt chunk size = %d, want at least 16", chunkSize)
			}
			if format := binary.LittleEndian.Uint16(body[dataStart : dataStart+2]); format != 1 {
				t.Errorf("AudioFormat = %d, want PCM format 1", format)
			}
		case "data":
			dataFound = true
			if chunkSize != 0 {
				t.Errorf("data chunk size = %d, want 0", chunkSize)
			}
		}
		offset = dataEnd + chunkSize%2
	}
	if !fmtFound || !dataFound {
		t.Fatalf("chunks found: fmt=%v data=%v, want both", fmtFound, dataFound)
	}
}

func TestMinimalMP4(t *testing.T) {
	asset, ok := Get("minimal-mp4")
	if !ok {
		t.Fatal("Get(minimal-mp4) returned ok=false")
	}
	body := asset.Body
	if len(body) < 8 || string(body[4:8]) != "ftyp" {
		t.Fatalf("first box is not ftyp: %x", body)
	}

	moovFound := false
	offset := 0
	for offset < len(body) {
		if offset+8 > len(body) {
			t.Fatalf("truncated box header at offset %d", offset)
		}
		size := int(binary.BigEndian.Uint32(body[offset : offset+4]))
		boxType := string(body[offset+4 : offset+8])
		if size < 8 {
			t.Fatalf("%s box size = %d, want at least 8", boxType, size)
		}
		if offset+size > len(body) {
			t.Fatalf("%s box at offset %d extends past body", boxType, offset)
		}
		if boxType == "moov" {
			moovFound = true
		}
		offset += size
	}
	if offset != len(body) {
		t.Fatalf("box sizes sum to %d, want %d", offset, len(body))
	}
	if !moovFound {
		t.Fatal("moov box not found")
	}
}

func TestTextAssetBodies(t *testing.T) {
	tests := map[string][]byte{
		"empty-js":   []byte("/* sinkhole */\n"),
		"empty-css":  []byte("/* sinkhole */\n"),
		"empty-text": {},
	}
	for name, want := range tests {
		asset, ok := Get(name)
		if !ok {
			t.Errorf("Get(%q) returned ok=false", name)
			continue
		}
		if !bytes.Equal(asset.Body, want) {
			t.Errorf("Get(%q).Body = %q, want %q", name, asset.Body, want)
		}
	}
}

func TestContentTypesAndSize(t *testing.T) {
	want := map[string]string{
		"blank-html":      "text/html; charset=utf-8",
		"empty-css":       "text/css",
		"empty-js":        "application/javascript",
		"empty-json":      "application/json",
		"empty-text":      "text/plain; charset=utf-8",
		"minimal-mp4":     "video/mp4",
		"silent-wav":      "audio/wav",
		"transparent-gif": "image/gif",
		"transparent-png": "image/png",
		"transparent-svg": "image/svg+xml",
	}
	for name, contentType := range want {
		asset, ok := Get(name)
		if !ok {
			t.Errorf("Get(%q) returned ok=false", name)
			continue
		}
		if asset.ContentType != contentType {
			t.Errorf("Get(%q).ContentType = %q, want %q", name, asset.ContentType, contentType)
		}
		if len(asset.Body) >= 1024 {
			t.Errorf("Get(%q) body length = %d, want under 1024", name, len(asset.Body))
		}
	}
}

func TestStubAssets(t *testing.T) {
	tests := []struct {
		name    string
		network string
		token   []byte
	}{
		{name: "stub-adsense", network: "adsense", token: []byte("adsbygoogle")},
		{name: "stub-gpt", network: "gpt", token: []byte("googletag")},
		{name: "stub-fbpixel", network: "fbpixel", token: []byte("fbq")},
		{name: "stub-ga", network: "ga", token: []byte("gtag")},
		{name: "stub-apstag", network: "apstag", token: []byte("apstag")},
		{name: "stub-prebid", network: "prebid", token: []byte("pbjs")},
		{name: "stub-cmp", network: "cmp", token: []byte("__tcfapi")},
		{name: "stub-antiadblock", network: "antiadblock", token: []byte("canRunAds")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			asset, ok := Get(test.name)
			if !ok {
				t.Fatalf("Get(%q) returned ok=false", test.name)
			}
			if asset.ContentType != "application/javascript" {
				t.Errorf("Get(%q).ContentType = %q, want application/javascript", test.name, asset.ContentType)
			}
			if len(asset.Body) == 0 {
				t.Errorf("Get(%q).Body is empty", test.name)
			}
			if !bytes.Contains(asset.Body, test.token) {
				t.Errorf("Get(%q).Body does not contain required token %q", test.name, test.token)
			}
			if !bytes.Contains(asset.Body, []byte("__sinkholeStubs")) {
				t.Errorf("Get(%q).Body does not contain the sinkhole marker", test.name)
			}
			marker := []byte(`["` + test.network + `"] = true`)
			if !bytes.Contains(asset.Body, marker) {
				t.Errorf("Get(%q).Body does not contain network marker %q", test.name, marker)
			}
		})
	}
}

func TestNamesMatchesEmbedded(t *testing.T) {
	names := Names()
	want := []string{
		"blank-html",
		"empty-css",
		"empty-js",
		"empty-json",
		"empty-text",
		"minimal-mp4",
		"silent-wav",
		"stub-adsense",
		"stub-antiadblock",
		"stub-apstag",
		"stub-cmp",
		"stub-fbpixel",
		"stub-ga",
		"stub-gpt",
		"stub-prebid",
		"transparent-gif",
		"transparent-png",
		"transparent-svg",
	}
	if len(names) != 18 {
		t.Fatalf("len(Names()) = %d, want 18", len(names))
	}
	if !slices.IsSorted(names) {
		t.Fatalf("Names() = %v, want sorted names", names)
	}
	if !slices.Equal(names, want) {
		t.Fatalf("Names() = %v, want %v", names, want)
	}

	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if _, duplicate := seen[name]; duplicate {
			t.Fatalf("Names() contains duplicate %q", name)
		}
		seen[name] = struct{}{}
		if _, ok := Get(name); !ok {
			t.Errorf("Get(%q) returned ok=false", name)
		}
	}
}

func TestGetUnknown(t *testing.T) {
	asset, ok := Get("nope")
	if ok {
		t.Fatal("Get(nope) returned ok=true")
	}
	if !reflect.DeepEqual(asset, Asset{}) {
		t.Fatalf("Get(nope) = %#v, want zero Asset", asset)
	}
}
