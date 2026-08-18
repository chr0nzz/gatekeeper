package templates

import (
	"html/template"
	"io/fs"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	gatekeeper "github.com/chr0nzz/gatekeeper"
)

func templateNames(t *testing.T) []string {
	t.Helper()
	var names []string
	err := fs.WalkDir(gatekeeper.Assets, "web/templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		names = append(names, d.Name())
		return nil
	})
	if err != nil {
		t.Fatalf("walk templates: %v", err)
	}
	if len(names) == 0 {
		t.Fatal("no templates found")
	}
	return names
}

func templateSources(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	fs.WalkDir(gatekeeper.Assets, "web/templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, readErr := fs.ReadFile(gatekeeper.Assets, path)
		if readErr == nil {
			out[path] = string(b)
		}
		return nil
	})
	return out
}

func TestAllTemplatesParse(t *testing.T) {
	r, err := New(gatekeeper.Assets, "web/templates")
	if err != nil {
		t.Fatalf("renderer init: %v", err)
	}

	for _, name := range templateNames(t) {
		t.Run(name, func(t *testing.T) {
			path, ok := r.index[name]
			if !ok {
				t.Fatalf("%s was not indexed by the renderer", name)
			}
			files := r.filesFor(name, path)
			if _, err := template.New("").Funcs(funcMap).ParseFS(r.fsys, files...); err != nil {
				t.Errorf("%s failed to parse: %v", name, err)
			}
		})
	}
}

func TestPageScopedVarsUseRootContext(t *testing.T) {
	pageVars := []string{"AdminBase", "CSRFToken"}
	rangeStart := regexp.MustCompile(`\{\{\s*range\b`)
	blockEnd := regexp.MustCompile(`\{\{\s*end\s*\}\}`)

	for path, src := range templateSources(t) {
		depth := 0
		for _, line := range strings.Split(src, "\n") {
			if depth > 0 {
				for _, v := range pageVars {
					if strings.Contains(line, "{{."+v+"}}") {
						t.Errorf("%s: {{.%s}} inside a range block, use {{$.%s}}\n  %s",
							filepath.Base(path), v, v, strings.TrimSpace(line))
					}
				}
			}
			depth += len(rangeStart.FindAllString(line, -1))
			if depth > 0 {
				depth -= len(blockEnd.FindAllString(line, -1))
			}
			if depth < 0 {
				depth = 0
			}
		}
	}
}

func TestInlineScriptsCarryNoncePlaceholder(t *testing.T) {
	for path, src := range templateSources(t) {
		if strings.Contains(src, "<script>") {
			t.Errorf("%s has an inline <script> without a nonce attribute", filepath.Base(path))
		}
	}
}

func TestNoInlineEventHandlers(t *testing.T) {
	handler := regexp.MustCompile(`(?:\s|\}\})on(click|change|input|error|load|submit|keyup|focus|blur)\s*=`)
	for path, src := range templateSources(t) {
		if m := handler.FindString(src); m != "" {
			t.Errorf("%s uses an inline event handler (%s), which CSP blocks", filepath.Base(path), strings.TrimSpace(m))
		}
	}
}

func TestStandaloneTemplatesSkipBaseLayout(t *testing.T) {
	for _, name := range []string{"admin_login.html", "admin_setup.html"} {
		if !isStandalone(name) {
			t.Errorf("%s should render without a base layout", name)
		}
	}
	if isStandalone("admin_users.html") {
		t.Error("admin_users.html should use the admin base layout")
	}
}

func TestUnknownTemplateReportsError(t *testing.T) {
	r, _ := New(gatekeeper.Assets, "web/templates")
	rec := httptest.NewRecorder()
	r.Render(rec, "does_not_exist.html", nil)
	if !strings.Contains(rec.Body.String(), "template not found") {
		t.Error("rendering an unknown template did not report an error")
	}
}
