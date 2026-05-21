package templates

import (
	"html/template"
	"io/fs"
	"net/http"
	"strings"
)

// Renderer renders page templates from an fs.FS, creating a fresh template set
// per render so {{define "content"}} blocks never bleed across pages.
type Renderer struct {
	fsys      fs.FS
	index     map[string]string
	userBase  string
	adminBase string
}

// New builds a Renderer from the given FS. templateRoot is the directory
// inside the FS containing the templates (e.g. "web/templates").
func New(fsys fs.FS, templateRoot string) (*Renderer, error) {
	r := &Renderer{
		fsys:  fsys,
		index: make(map[string]string),
	}
	err := fs.WalkDir(fsys, templateRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		r.index[d.Name()] = path
		return nil
	})
	if err != nil {
		return nil, err
	}
	r.userBase = r.index["base.html"]
	r.adminBase = r.index["admin_base.html"]
	return r, nil
}

// Render writes the named template to w, including only the correct base layout.
func (r *Renderer) Render(w http.ResponseWriter, name string, data interface{}) {
	path, ok := r.index[name]
	if !ok {
		http.Error(w, "template not found: "+name, http.StatusInternalServerError)
		return
	}

	files := r.filesFor(name, path)
	tmpl, err := template.New("").ParseFS(r.fsys, files...)
	if err != nil {
		http.Error(w, "template parse error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "template render error: "+err.Error(), http.StatusInternalServerError)
	}
}

func (r *Renderer) filesFor(name, path string) []string {
	if isStandalone(name) {
		return []string{path}
	}
	if strings.Contains(path, "/admin/") {
		return []string{r.adminBase, path}
	}
	return []string{r.userBase, path}
}

func isStandalone(name string) bool {
	return name == "admin_login.html" || name == "admin_setup.html"
}
