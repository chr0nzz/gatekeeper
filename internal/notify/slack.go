package notify

import "time"

func sendSlack(url, event, msg string) error {
	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"title":  event,
				"text":   msg,
				"color":  slackColor(event),
				"footer": "GateKeeper",
				"ts":     time.Now().Unix(),
			},
		},
	}
	return postJSON(url, payload)
}

func slackColor(event string) string {
	switch {
	case containsStr(event, "failure") || containsStr(event, "failed") || containsStr(event, "invalid"):
		return "danger"
	case containsStr(event, "recovery") || containsStr(event, "revoked") || containsStr(event, "disabled"):
		return "warning"
	default:
		return "good"
	}
}
