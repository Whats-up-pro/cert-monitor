// File: cmd/cert-monitor/main.go
package main

import (
	"cert-monitor/internal/checker"
	"cert-monitor/internal/config"
	"cert-monitor/internal/evaluator"
	"fmt"
	"log"
)

func main() {
	// 1. Load configuration from config.toml
	cfg, err := config.Load("config.toml")
	if err != nil {
		log.Fatalf("Failed to load configuration from 'config.toml'. Error: %v", err)
	}

	fmt.Println("Starting to check domains...")
	
	// A flag to see if any alert was triggered
	foundAlerts := false

	// 2. Loop through the domains from the config.
	for _, domain := range cfg.Settings.Domains {
		expiryDate, err := checker.CheckHost(domain)
		if err != nil {
			fmt.Printf(" - [ERROR] %s: %v\n", domain, err)
			foundAlerts = true
			continue // Move to the next domain
		}

		// 3. Evaluate the result
		alertInfo := evaluator.Evaluate(domain, expiryDate, cfg.Settings.AlertThresholds)

		// 4. Print the result or alert
		if alertInfo.ShouldAlert {
			fmt.Printf(" - %s\n", alertInfo.Message)
			foundAlerts = true
		} else {
			// Optional: You can print OK statuses for verbosity, or comment this out.
			fmt.Printf(" - %s\n", alertInfo.Message)
		}
	}
	
	if !foundAlerts {
		fmt.Println("All certificates are OK.")
	}
}