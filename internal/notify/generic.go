package notify

import "time"

func sendGeneric(url, event, userID, ip, detail string) error {
	payload := map[string]interface{}{
		"event":     event,
		"user_id":   userID,
		"ip":        ip,
		"detail":    detail,
		"timestamp": time.Now().Unix(),
		"source":    "gatekeeper",
	}
	return postJSON(url, payload)
}
