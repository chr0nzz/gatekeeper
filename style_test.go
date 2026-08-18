package gatekeeper

import (
	"go/ast"
	"go/parser"
	"go/token"
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

func TestNoCommentsInsideFunctionBodies(t *testing.T) {
	fset := token.NewFileSet()
	for _, path := range styleGoFiles(t) {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		var bodies []*ast.BlockStmt
		ast.Inspect(f, func(n ast.Node) bool {
			if fn, ok := n.(*ast.FuncDecl); ok && fn.Body != nil {
				bodies = append(bodies, fn.Body)
			}
			return true
		})
		for _, cg := range f.Comments {
			if styleIsDirective(cg.List[0].Text) {
				continue
			}
			for _, b := range bodies {
				if cg.Pos() > b.Lbrace && cg.End() < b.Rbrace {
					t.Errorf("%s:%d: comment inside a function body, name things clearly instead\n  %s",
						path, fset.Position(cg.Pos()).Line, strings.TrimSpace(cg.List[0].Text))
				}
			}
		}
	}
}

func TestTestFilesCarryNoComments(t *testing.T) {
	for _, path := range styleGoFiles(t) {
		if !strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") && !styleIsDirective(trimmed) {
				t.Errorf("%s:%d: test files carry no comments\n  %s", path, i+1, trimmed)
			}
		}
	}
}

func TestDocCommentsAreASingleLine(t *testing.T) {
	fset := token.NewFileSet()
	for _, path := range styleGoFiles(t) {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		check := func(doc *ast.CommentGroup, name string) {
			if doc == nil || len(doc.List) <= 1 {
				return
			}
			if strings.HasPrefix(doc.List[0].Text, "//go:") {
				return
			}
			t.Errorf("%s:%d: doc comment on %s spans %d lines, exported symbols get one line only",
				path, fset.Position(doc.Pos()).Line, name, len(doc.List))
		}
		for _, d := range f.Decls {
			switch decl := d.(type) {
			case *ast.FuncDecl:
				check(decl.Doc, decl.Name.Name)
			case *ast.GenDecl:
				check(decl.Doc, "declaration")
			}
		}
	}
}

func styleGoFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "docs" || d.Name() == "node_modules" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return out
}

func styleIsDirective(text string) bool {
	return strings.HasPrefix(text, "//go:") || strings.HasPrefix(text, "//nolint")
}
