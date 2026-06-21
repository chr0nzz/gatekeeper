package admin

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/go-chi/chi/v5"
	gkbackup "github.com/chr0nzz/gatekeeper/internal/backup"
)

func (h *Handlers) GetBackups(w http.ResponseWriter, r *http.Request) {
	backups, _ := h.backups.List(r.Context())

	get := func(k, def string) string { return h.settings.Get(r.Context(), k, def) }

	h.render(w, r, "admin_backups.html", map[string]interface{}{
		"Backups":          backups,
		"StorageType":      get("backup_storage", ""),
		"LocalPath":        get("backup_local_path", ""),
		"S3Endpoint":       get("backup_s3_endpoint", ""),
		"S3Bucket":         get("backup_s3_bucket", ""),
		"S3AccessKey":      get("backup_s3_access_key", ""),
		"S3Region":         get("backup_s3_region", "us-east-1"),
		"S3Prefix":         get("backup_s3_prefix", "gatekeeper/"),
		"S3PathStyle":      get("backup_s3_path_style", "false"),
		"Schedule":         get("backup_schedule", "manual"),
		"Retention":        get("backup_retention", "10"),
		"Error":            r.URL.Query().Get("err"),
		"Success":          r.URL.Query().Get("ok"),
	})
}

func (h *Handlers) PostBackupSettings(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	set := func(k, v string) { h.settings.Set(r.Context(), k, v) }

	set("backup_storage", r.FormValue("backup_storage"))
	set("backup_local_path", r.FormValue("backup_local_path"))
	set("backup_s3_endpoint", r.FormValue("backup_s3_endpoint"))
	set("backup_s3_bucket", r.FormValue("backup_s3_bucket"))
	set("backup_s3_access_key", r.FormValue("backup_s3_access_key"))
	if v := r.FormValue("backup_s3_secret_key"); v != "" {
		set("backup_s3_secret_key", v)
	}
	set("backup_s3_region", r.FormValue("backup_s3_region"))
	set("backup_s3_prefix", r.FormValue("backup_s3_prefix"))
	set("backup_s3_path_style", r.FormValue("backup_s3_path_style"))
	set("backup_schedule", r.FormValue("backup_schedule"))
	set("backup_retention", r.FormValue("backup_retention"))

	http.Redirect(w, r, h.adminBase + "/backups?ok=Settings+saved", http.StatusSeeOther)
}

func (h *Handlers) PostBackupNow(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	storage := gkbackup.BuildStorage(h.settings)
	if storage == nil {
		http.Redirect(w, r, h.adminBase + "/backups?err=Configure+storage+before+running+a+backup", http.StatusSeeOther)
		return
	}

	retentionStr := h.settings.Get(r.Context(), "backup_retention", "10")
	retention, _ := strconv.Atoi(retentionStr)
	if retention <= 0 {
		retention = 10
	}

	if err := gkbackup.RunBackup(r.Context(), h.db, h.dbPath, []byte(h.secretKey), storage, h.backups, retention); err != nil {
		http.Redirect(w, r, h.adminBase + "/backups?err="+encodeMsg(err.Error()), http.StatusSeeOther)
		return
	}

	h.auditLog.Log(r.Context(), "backup.created", "", h.adminIDFromRequest(r), r.RemoteAddr, "manual")
	http.Redirect(w, r, h.adminBase + "/backups?ok=Backup+completed+successfully", http.StatusSeeOther)
}

func (h *Handlers) GetBackupDownload(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rec, err := h.backups.GetByID(r.Context(), id)
	if err != nil || rec == nil {
		http.NotFound(w, r)
		return
	}

	storage := gkbackup.BuildStorage(h.settings)
	if storage == nil {
		http.Error(w, "storage not configured", http.StatusServiceUnavailable)
		return
	}

	data, err := storage.Download(r.Context(), rec.Name)
	if err != nil {
		http.Error(w, "download failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, rec.Name))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}

func (h *Handlers) PostBackupRestore(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	id := chi.URLParam(r, "id")
	rec, err := h.backups.GetByID(r.Context(), id)
	if err != nil || rec == nil {
		http.NotFound(w, r)
		return
	}

	storage := gkbackup.BuildStorage(h.settings)
	if storage == nil {
		http.Redirect(w, r, h.adminBase + "/backups?err=Storage+not+configured", http.StatusSeeOther)
		return
	}

	encrypted, err := storage.Download(r.Context(), rec.Name)
	if err != nil {
		http.Redirect(w, r, h.adminBase + "/backups?err="+encodeMsg("Download failed: "+err.Error()), http.StatusSeeOther)
		return
	}

	plain, err := gkbackup.Decrypt(encrypted, []byte(h.secretKey))
	if err != nil {
		http.Redirect(w, r, h.adminBase + "/backups?err="+encodeMsg("Decrypt failed - wrong SECRET_KEY or corrupt backup"), http.StatusSeeOther)
		return
	}

	restorePath := h.dbPath + ".restore"
	if err := os.WriteFile(restorePath, plain, 0600); err != nil {
		http.Redirect(w, r, h.adminBase + "/backups?err="+encodeMsg("Write failed: "+err.Error()), http.StatusSeeOther)
		return
	}

	h.auditLog.Log(r.Context(), "backup.restored", "", h.adminIDFromRequest(r), r.RemoteAddr, rec.Name)

	http.Redirect(w, r, h.adminBase + "/backups?ok="+encodeMsg(
		"Restore staged. Restart GateKeeper now to complete the restore - the backup is applied automatically on startup. All sessions will be reset.",
	), http.StatusSeeOther)
}

// PostBackupUpload accepts an encrypted backup file, decrypts it, and stages it for restore on next restart.
func (h *Handlers) PostBackupUpload(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	if err := r.ParseMultipartForm(64 << 20); err != nil {
		http.Redirect(w, r, h.adminBase+"/backups?err="+encodeMsg("Upload too large or malformed"), http.StatusSeeOther)
		return
	}
	file, _, err := r.FormFile("backup")
	if err != nil {
		http.Redirect(w, r, h.adminBase+"/backups?err="+encodeMsg("No file uploaded"), http.StatusSeeOther)
		return
	}
	defer file.Close()

	encrypted, err := io.ReadAll(file)
	if err != nil {
		http.Redirect(w, r, h.adminBase+"/backups?err="+encodeMsg("Read failed: "+err.Error()), http.StatusSeeOther)
		return
	}

	plain, err := gkbackup.Decrypt(encrypted, []byte(h.secretKey))
	if err != nil {
		http.Redirect(w, r, h.adminBase+"/backups?err="+encodeMsg("Decrypt failed - this backup was not encrypted with the current SECRET_KEY, or the file is corrupt"), http.StatusSeeOther)
		return
	}
	if !bytes.HasPrefix(plain, []byte("SQLite format 3\x00")) {
		http.Redirect(w, r, h.adminBase+"/backups?err="+encodeMsg("Decrypted file is not a valid GateKeeper database"), http.StatusSeeOther)
		return
	}

	if err := os.WriteFile(h.dbPath+".restore", plain, 0600); err != nil {
		http.Redirect(w, r, h.adminBase+"/backups?err="+encodeMsg("Write failed: "+err.Error()), http.StatusSeeOther)
		return
	}

	h.auditLog.Log(r.Context(), "backup.uploaded", "", h.adminIDFromRequest(r), r.RemoteAddr, "")

	http.Redirect(w, r, h.adminBase+"/backups?ok="+encodeMsg(
		"Backup uploaded and staged. Restart GateKeeper now to complete the restore. All sessions will be reset.",
	), http.StatusSeeOther)
}

func (h *Handlers) PostBackupDelete(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	id := chi.URLParam(r, "id")
	rec, err := h.backups.GetByID(r.Context(), id)
	if err != nil || rec == nil {
		http.NotFound(w, r)
		return
	}

	storage := gkbackup.BuildStorage(h.settings)
	if storage != nil {
		storage.Delete(r.Context(), rec.Name)
	}

	h.backups.Delete(r.Context(), id)
	h.auditLog.Log(r.Context(), "backup.deleted", "", h.adminIDFromRequest(r), r.RemoteAddr, rec.Name)
	http.Redirect(w, r, h.adminBase + "/backups?ok=Backup+deleted", http.StatusSeeOther)
}

func encodeMsg(s string) string {
	var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			out = append(out, c)
		} else if c == ' ' {
			out = append(out, '+')
		} else {
			out = append(out, '%', "0123456789ABCDEF"[c>>4], "0123456789ABCDEF"[c&0xf])
		}
	}
	return string(out)
}
