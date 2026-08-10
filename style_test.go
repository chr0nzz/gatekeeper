package gatekeeper

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var styleCheckedExtensions = map[string]bool{
	".go":   true,
	".md":   true,
	".html": true,
	".css":  true,
	".js":   true,
	".sql":  true,
	".yml":  true,
	".yaml": true,
}

var styleSkippedDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"dist":         true,
	"screenshots":  true,
}

// walkSourceFiles visits every hand-written source and documentation file,
// skipping vendored, generated, and binary content.
func walkSourceFiles(t *testing.T, visit func(path, content string)) {
	t.Helper()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if styleSkippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !styleCheckedExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		visit(path, string(body))
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// The project writes hyphens rather than em or en dashes, in code comments,
// interface copy, and documentation alike.
func TestNoDashesInPlaceOfHyphens(t *testing.T) {
	banned := map[string]string{
		"\u2014": "em dash",
		"\u2013": "en dash",
	}
	found := 0
	walkSourceFiles(t, func(path, content string) {
		for _, line := range strings.Split(content, "\n") {
			for char, name := range banned {
				if strings.Contains(line, char) {
					found++
					if found <= 20 {
						t.Errorf("%s: %s found, use a hyphen instead\n  %s",
							path, name, strings.TrimSpace(line))
					}
				}
			}
		}
	})
	if found > 20 {
		t.Errorf("%d further occurrences not shown", found-20)
	}
}

// Smart quotes come from pasting out of a word processor and break code and
// shell snippets that readers copy out of the documentation.
func TestNoSmartQuotes(t *testing.T) {
	banned := []string{"\u201c", "\u201d", "\u2018", "\u2019"}
	walkSourceFiles(t, func(path, content string) {
		for _, line := range strings.Split(content, "\n") {
			for _, char := range banned {
				if strings.Contains(line, char) {
					t.Errorf("%s: smart quote found, use a straight quote\n  %s",
						path, strings.TrimSpace(line))
					return
				}
			}
		}
	})
}

// A stray merge marker committed to the tree breaks the build in ways that are
// slow to diagnose.
func TestNoConflictMarkers(t *testing.T) {
	walkSourceFiles(t, func(path, content string) {
		for _, line := range strings.Split(content, "\n") {
			if strings.HasPrefix(line, "<<<<<<< ") || strings.HasPrefix(line, ">>>>>>> ") {
				t.Errorf("%s: unresolved merge conflict marker: %s", path, strings.TrimSpace(line))
				return
			}
		}
	})
}
