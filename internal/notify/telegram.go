package notify

import "fmt"

func sendTelegram(token, chatID, msg string) error {
	if token == "" || chatID == "" {
		return fmt.Errorf("telegram token and chat_id are required")
	}
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       msg,
		"parse_mode": "HTML",
	}
	return postJSON(url, payload)
}
