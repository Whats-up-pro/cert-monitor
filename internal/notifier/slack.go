// File: internal/notifier/slack.go
package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SlackNotifier implements the Notifier interface for Slack.
type SlackNotifier struct {
	WebhookURL string
}

// NewSlackNotifier creates a new instance of SlackNotifier.
func NewSlackNotifier(webhookURL string) *SlackNotifier {
	return &SlackNotifier{WebhookURL: webhookURL}
}

// Send sends a message to the configured Slack webhook URL.
func (s *SlackNotifier) Send(message string) error {
	// Create the JSON payload for the Slack message.
	// Using a map[string]string for a simple text message.
	payload := map[string]string{"text": message}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal slack payload: %w", err)
	}

	// Create the HTTP POST request.
	req, err := http.NewRequest("POST", s.WebhookURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Send the request using a client with a timeout.
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send slack notification: %w", err)
	}
	defer resp.Body.Close()

	// Check for a successful response from Slack.
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-200 response from slack: %s", resp.Status)
	}

	return nil
}