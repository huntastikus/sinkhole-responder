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
	authedPages := []string{
		"index.html",
		"config.html",
		"rules.html",
		"rulepacks.html",
		"tls.html",
		"tools.html",
		"detector.html",
		"logs.html",
		"wizard.html",
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
