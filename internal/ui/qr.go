package ui

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/chr0nzz/gatekeeper/internal/auth"
	qrcode "github.com/skip2/go-qrcode"
)

func (h *Handlers) PostQRBegin(w http.ResponseWriter, r *http.Request) {
	oidcRequest := r.URL.Query().Get("oidc_request")
	redirectURI := r.URL.Query().Get("redirect_uri")
	id, err := h.qrTokens.Create(r.Context(), oidcRequest, redirectURI)
	if err != nil {
		http.Error(w, "failed to create token", http.StatusInternalServerError)
		return
	}
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
	tok, err := h.qrTokens.Get(r.Context(), id)
	w.Header().Set("Content-Type", "application/json")
	if err != nil || tok == nil || time.Now().Unix() > tok.ExpiresAt {
		json.NewEncoder(w).Encode(map[string]string{"status": "expired"})
		return
	}
	if tok.Status != "approved" {
		json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
		return
	}
	sessData := auth.SessionData{UserID: tok.UserID, OIDCRequestID: tok.OIDCRequest, RedirectURI: tok.RedirectURI}
	_, err = h.sessions.Create(w, r, sessData)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	h.qrTokens.Cleanup(r.Context())
	redirect := "/"
	if tok.OIDCRequest != "" && h.oidcStorage != nil {
		if authErr := h.oidcStorage.AuthRequestDone(r.Context(), tok.OIDCRequest, tok.UserID); authErr == nil {
			redirect = "/authorize/callback?id=" + tok.OIDCRequest
		}
	} else if tok.RedirectURI != "" {
		redirect = tok.RedirectURI
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "approved", "redirect": redirect})
}

func (h *Handlers) GetQRApprove(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("token")
	tok, err := h.qrTokens.Get(r.Context(), id)
	if err != nil || tok == nil || time.Now().Unix() > tok.ExpiresAt {
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
	h.render(w, "qr_approve.html", map[string]interface{}{"Token": id, "Name": name})
}

func (h *Handlers) PostQRApprove(w http.ResponseWriter, r *http.Request) {
	sess, _, _ := h.sessions.Get(r)
	if sess == nil || sess.UserID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	id := r.FormValue("token")
	tok, err := h.qrTokens.Get(r.Context(), id)
	if err != nil || tok == nil || time.Now().Unix() > tok.ExpiresAt {
		h.render(w, "qr_expired.html", nil)
		return
	}
	if err := h.qrTokens.Approve(r.Context(), id, sess.UserID); err != nil {
		http.Error(w, "failed to approve", http.StatusInternalServerError)
		return
	}
	h.render(w, "qr_approved.html", nil)
}
