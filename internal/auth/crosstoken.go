package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

const crossTokenTTL = 5 * time.Minute

// GenerateCrossToken creates a short-lived HMAC-signed token carrying a session ID.
// Used to hand off an authenticated session to a different domain.
func GenerateCrossToken(sessionID, secretKey string) string {
	expiry := strconv.FormatInt(time.Now().Add(crossTokenTTL).Unix(), 10)
	payload := sessionID + ":" + expiry
	sig := crossSign(payload, secretKey)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
}

// ValidateCrossToken verifies the token signature and expiry, returning the session ID.
func ValidateCrossToken(token, secretKey string) (string, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", errors.New("invalid token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("invalid token encoding")
	}
	payload := string(raw)
	if !hmac.Equal([]byte(parts[1]), []byte(crossSign(payload, secretKey))) {
		return "", errors.New("invalid token signature")
	}
	idx := strings.LastIndex(payload, ":")
	if idx < 0 {
		return "", errors.New("malformed token")
	}
	expiry, err := strconv.ParseInt(payload[idx+1:], 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		return "", errors.New("token expired")
	}
	return payload[:idx], nil
}

func crossSign(payload, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
