package notify

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/chr0nzz/gatekeeper/internal/httpguard"
)

func sendNtfy(baseURL, topic, username, password, event, msg string) error {
	if topic == "" {
		return fmt.Errorf("ntfy topic is required")
	}
	baseURL = strings.TrimRight(baseURL, "/")
	url := fmt.Sprintf("%s/%s", baseURL, topic)
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(msg))
	if err != nil {
		return err
	}
	req.Header.Set("Title", "GateKeeper: "+event)
	req.Header.Set("Content-Type", "text/plain")
	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}
	resp, err := httpguard.Client(15 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
