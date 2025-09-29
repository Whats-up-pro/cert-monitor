// File: cmd/cert-monitor/main.go
package main

import (
	"cert-monitor/internal/checker"
	"cert-monitor/internal/config"
	"cert-monitor/internal/evaluator"
	"cert-monitor/internal/notifier"
	"fmt"
	"log"
	"os"
)

func main() {
	// 1. Load configuration
	cfg, err := config.Load("config.toml")
	if err != nil {
		log.Fatalf("Failed to load configuration from 'config.toml'. Error: %v", err)
	}

	// --- Initialize Notifiers ---
	var slackNotifier *notifier.SlackNotifier
	if cfg.Notifications.Slack.Enabled {
		webhookURL := os.Getenv(cfg.Notifications.Slack.WebhookURLEnvVar)
		if webhookURL == "" {
			log.Fatalf("Slack is enabled, but the environment variable %s is not set.", cfg.Notifications.Slack.WebhookURLEnvVar)
		}
		slackNotifier = notifier.NewSlackNotifier(webhookURL)
		log.Println("Slack notifier is enabled.")
	}
	// --- End Notifier Initialization ---

	fmt.Println("Starting to check domains...")

	var foundAlerts bool

	// 2. Loop through domains and check them
	for _, domain := range cfg.Settings.Domains {
		expiryDate, err := checker.CheckHost(domain)
		if err != nil {
			// Handle connection or check errors
			errorMessage := fmt.Sprintf("[ERROR] Could not check %s: %v", domain, err)
			fmt.Println(errorMessage)
			if slackNotifier != nil {
				_ = slackNotifier.Send(errorMessage) // Send error to Slack
			}
			foundAlerts = true
			continue // Move to the next domain
		}

		// 3. Evaluate the certificate status
		alertInfo := evaluator.Evaluate(domain, expiryDate, cfg.Settings.AlertThresholds)

		// 4. Send alert if needed, otherwise print OK status
		if alertInfo.ShouldAlert {
			fmt.Println(alertInfo.Message)
			if slackNotifier != nil {
				err := slackNotifier.Send(alertInfo.Message)
				if err != nil {
					log.Printf("Failed to send slack notification for %s: %v", domain, err)
				}
			}
			foundAlerts = true
		} else {
			// Optional: print OK status for verbosity.
			fmt.Println(alertInfo.Message)
		}
	}

	if !foundAlerts {
		fmt.Println("All certificates are OK.")
	}
}