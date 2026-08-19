package ui

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/chr0nzz/gatekeeper/internal/auth"
	qrcode "github.com/skip2/go-qrcode"
)

const qrBindingCookie = "gk_qr"

func qrBindingHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func (h *Handlers) PostQRBegin(w http.ResponseWriter, r *http.Request) {
	oidcRequest := r.URL.Query().Get("oidc_request")
	redirectURI := h.redirects.Sanitize(r.URL.Query().Get("redirect_uri"))
	secret, err := auth.RandomTokenExport(32)
	if err != nil {
		http.Error(w, "failed to create token", http.StatusInternalServerError)
		return
	}
	id, err := h.qrTokens.Create(r.Context(), oidcRequest, redirectURI, qrBindingHash(secret))
	if err != nil {
		http.Error(w, "failed to create token", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     qrBindingCookie,
		Value:    secret,
		Path:     "/login/qr",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	approveURL := h.baseURL + "/login/qr/approve?token=" + id
	png, err := qrcode.Encode(approveURL, qrcode.Medium, 240)
	if err != nil {
		http.Error(w, "failed to generate qr", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": id,
		"qr":    "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
	})
}

func (h *Handlers) GetQRPoll(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("token")
	w.Header().Set("Content-Type", "application/json")

	binding := ""
	if c, err := r.Cookie(qrBindingCookie); err == nil {
		binding = qrBindingHash(c.Value)
	}
	if binding == "" {
		json.NewEncoder(w).Encode(map[string]string{"status": "expired"})
		return
	}

	tok, err := h.qrTokens.Get(r.Context(), id)
	if err != nil || tok == nil || time.Now().Unix() > tok.ExpiresAt || tok.Status == "used" {
		json.NewEncoder(w).Encode(map[string]string{"status": "expired"})
		return
	}
	if tok.Status != "approved" {
		json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
		return
	}

	claimed, err := h.qrTokens.Consume(r.Context(), id, binding)
	if err != nil || claimed == nil {
		json.NewEncoder(w).Encode(map[string]string{"status": "expired"})
		return
	}

	sessData := auth.SessionData{UserID: claimed.UserID, OIDCRequestID: claimed.OIDCRequest, RedirectURI: claimed.RedirectURI}
	if _, err := h.sessions.Create(w, r, sessData); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: qrBindingCookie, Value: "", Path: "/login/qr", MaxAge: -1, HttpOnly: true, Secure: true})
	h.auditLog.Log(r.Context(), "login.qr", claimed.UserID, h.loginActor(r.Context(), claimed.OIDCRequest, claimed.RedirectURI), r.RemoteAddr, "")
	h.qrTokens.Cleanup(r.Context())

	redirect := "/"
	if claimed.OIDCRequest != "" && h.oidcStorage != nil {
		if authErr := h.oidcStorage.AuthRequestDone(r.Context(), claimed.OIDCRequest, claimed.UserID); authErr == nil {
			redirect = "/authorize/callback?id=" + claimed.OIDCRequest
		}
	} else if claimed.RedirectURI != "" {
		redirect = h.redirectURL(r.Context(), claimed.UserID, claimed.RedirectURI)
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "approved", "redirect": redirect})
}

func (h *Handlers) GetQRApprove(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("token")
	tok, err := h.qrTokens.Get(r.Context(), id)
	if err != nil || tok == nil || time.Now().Unix() > tok.ExpiresAt || tok.Status != "pending" {
		h.render(w, "qr_expired.html", nil)
		return
	}
	sess, _, _ := h.sessions.Get(r)
	if sess == nil || sess.UserID == "" || sess.PendingOTP || sess.PendingTOTP {
		http.Redirect(w, r, "/login?redirect_uri=/login/qr/approve%3Ftoken%3D"+id, http.StatusFound)
		return
	}
	user, _ := h.users.GetByID(r.Context(), sess.UserID)
	name := ""
	if user != nil {
		if user.DisplayName != "" {
			name = user.DisplayName
		} else {
			name = user.Email
		}
	}
	h.render(w, "qr_approve.html", map[string]interface{}{
		"Token":     id,
		"Name":      name,
		"CSRFToken": h.csrf(r),
	})
}

func (h *Handlers) PostQRApprove(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	sess, _, _ := h.sessions.Get(r)
	if sess == nil || sess.UserID == "" || sess.PendingOTP || sess.PendingTOTP {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	id := r.FormValue("token")
	tok, err := h.qrTokens.Get(r.Context(), id)
	if err != nil || tok == nil || time.Now().Unix() > tok.ExpiresAt || tok.Status != "pending" {
		h.render(w, "qr_expired.html", nil)
		return
	}
	if err := h.qrTokens.Approve(r.Context(), id, sess.UserID); err != nil {
		http.Error(w, "failed to approve", http.StatusInternalServerError)
		return
	}
	h.auditLog.Log(r.Context(), "login.qr_approved", sess.UserID, "", r.RemoteAddr, "")
	h.render(w, "qr_approved.html", nil)
}
