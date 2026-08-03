package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/chr0nzz/gatekeeper/internal/httpguard"
)

func sendDiscord(url, event, msg string) error {
	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       event,
				"description": msg,
				"color":       colorForEvent(event),
				"timestamp":   time.Now().UTC().Format(time.RFC3339),
				"footer":      map[string]string{"text": "GateKeeper"},
			},
		},
	}
	return postJSON(url, payload)
}

func colorForEvent(event string) int {
	switch {
	case event == "login.failure" || contains(event, "failed") || contains(event, "invalid"):
		return 0xED4245
	case contains(event, "warn") || contains(event, "recovery") || contains(event, "revoked") || contains(event, "disabled"):
		return 0xFEE75C
	default:
		return 0x57F287
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func postJSON(url string, payload interface{}) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := httpguard.ValidateURL(url); err != nil {
		return err
	}
	resp, err := httpguard.Client(15*time.Second).Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
