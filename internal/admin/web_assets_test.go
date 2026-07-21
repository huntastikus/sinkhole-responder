package admin

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

func TestWebAssetsHaveNoExternalReferences(t *testing.T) {
	externalReferences := []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script\b[^>]*\bsrc\s*=\s*["']\s*(?:https?:)?//`),
		regexp.MustCompile(`(?i)<link\b[^>]*\bhref\s*=\s*["']\s*(?:https?:)?//`),
		regexp.MustCompile(`(?i)@font-face\b`),
		regexp.MustCompile(`(?i)url\(\s*["']?\s*(?:https?:)?//`),
	}

	err := fs.WalkDir(embeddedWeb, "web", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || (!strings.HasSuffix(path, ".html") && !strings.HasSuffix(path, ".css") && !strings.HasSuffix(path, ".js")) {
			return nil
		}

		content, err := fs.ReadFile(embeddedWeb, path)
		if err != nil {
			return err
		}
		for _, pattern := range externalReferences {
			if match := pattern.Find(content); match != nil {
				t.Errorf("%s contains external asset reference %q", path, match)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded web assets: %v", err)
	}
}

func TestWebAssetsWireSharedNavigation(t *testing.T) {
	var authedPages []string
	err := fs.WalkDir(embeddedWeb, "web", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".html") || path == "web/login.html" || path == "web/setup.html" {
			return nil
		}
		authedPages = append(authedPages, strings.TrimPrefix(path, "web/"))
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded web assets: %v", err)
	}

	for _, name := range authedPages {
		t.Run(name, func(t *testing.T) {
			content, err := fs.ReadFile(embeddedWeb, "web/"+name)
			if err != nil {
				t.Fatalf("read embedded page: %v", err)
			}
			page := string(content)
			if !strings.Contains(page, `id="app-nav"`) {
				t.Error("missing shared navigation placeholder")
			}
			if !strings.Contains(page, `src="/assets/nav.js"`) {
				t.Error("missing shared navigation module")
			}
			if !strings.Contains(page, `rel="help" href="/help/"`) {
				t.Error("missing help link")
			}
		})
	}

	nav, err := fs.ReadFile(embeddedWeb, "web/nav.js")
	if err != nil {
		t.Fatalf("read shared navigation module: %v", err)
	}
	if !strings.Contains(string(nav), `"/help/"`) {
		t.Error("shared navigation module is missing the /help/ link")
	}
	for _, want := range []string{`id = "system-health-button"`, `id = "system-health-panel"`, `sinkhole:nav-ready`} {
		if !strings.Contains(string(nav), want) {
			t.Errorf("shared navigation module is missing health control wiring %q", want)
		}
	}

	for _, name := range []string{"login.html", "setup.html"} {
		t.Run(name+"_pre_auth", func(t *testing.T) {
			content, err := fs.ReadFile(embeddedWeb, "web/"+name)
			if err != nil {
				t.Fatalf("read embedded page: %v", err)
			}
			if strings.Contains(string(content), `id="app-nav"`) {
				t.Error("pre-auth page must not include the shared navigation")
			}
		})
	}
}

func TestWebAssetsWireSharedBranding(t *testing.T) {
	t.Parallel()

	logo, err := fs.ReadFile(embeddedWeb, "web/logo.svg")
	if err != nil {
		t.Fatalf("read embedded logo: %v", err)
	}
	if !strings.Contains(string(logo), `<title id="title">Sinkhole Responder</title>`) {
		t.Error("embedded logo is missing its accessible title")
	}

	nav, err := fs.ReadFile(embeddedWeb, "web/nav.js")
	if err != nil {
		t.Fatalf("read shared navigation module: %v", err)
	}
	if !strings.Contains(string(nav), `brandLogo.src = "/assets/logo.svg"`) {
		t.Error("shared navigation does not use the embedded logo")
	}

	for _, name := range []string{"login.html", "setup.html"} {
		t.Run(name, func(t *testing.T) {
			content, err := fs.ReadFile(embeddedWeb, "web/"+name)
			if err != nil {
				t.Fatalf("read embedded page: %v", err)
			}
			page := string(content)
			if !strings.Contains(page, `class="auth-mark" src="/assets/logo.svg"`) {
				t.Error("auth page does not use the embedded logo")
			}
			if !strings.Contains(page, `rel="icon" href="/assets/logo.svg" type="image/svg+xml"`) {
				t.Error("auth page does not use the embedded logo as its favicon")
			}
		})
	}
}

func TestLoginIncludesVersionPlaceholder(t *testing.T) {
	t.Parallel()

	content, err := fs.ReadFile(embeddedWeb, "web/login.html")
	if err != nil {
		t.Fatalf("read login page: %v", err)
	}
	if !strings.Contains(string(content), `class="auth-version">{{.Version}}`) {
		t.Error("login page is missing the build version placeholder")
	}
}

func TestRequestBodyLoggingUIWarnsAboutSensitiveData(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		want []string
	}{
		{
			name: "config.html",
			want: []string{
				`data-config-path="logging.log_request_body"`,
				`data-config-path="logging.request_body_log_max_bytes"`,
				`data-request-body-method`,
				`value="DELETE"`,
				"Sensitive-data risk",
				"Redaction is best-effort",
			},
		},
		{
			name: "logs.html",
			want: []string{
				"may contain sensitive data",
				"disable body logging after troubleshooting",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			content, err := fs.ReadFile(embeddedWeb, "web/"+test.name)
			if err != nil {
				t.Fatalf("read embedded page: %v", err)
			}
			page := string(content)
			for _, want := range test.want {
				if !strings.Contains(page, want) {
					t.Errorf("page is missing %q", want)
				}
			}
		})
	}
}
