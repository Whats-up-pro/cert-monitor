// File: cmd/cert-monitor/main.go
package main

import (
	"cert-monitor/internal/checker"
	"cert-monitor/internal/config"
	"cert-monitor/internal/evaluator"
	"cert-monitor/internal/notifier"
	"flag" 
	"fmt"
	"log"
	"os"
	"sync"
	"time" 
	"runtime"
)

func printMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// m.Alloc là bộ nhớ heap hiện tại đang được sử dụng.
	// m.TotalAlloc là tổng bộ nhớ heap đã được cấp phát (sẽ luôn tăng).
	// Chuyển đổi sang MiB.
	fmt.Printf("Alloc = %v MiB", m.Alloc/1024/1024)
	fmt.Printf("\tTotalAlloc = %v MiB", m.TotalAlloc/1024/1024)
	fmt.Printf("\tSys = %v MiB", m.Sys/1024/1024)
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
}


// CheckResult struct to hold results from concurrent workers.
type CheckResult struct {
	Domain     string
	ExpiryDate time.Time
	Err        error
}

func main() {
	// --- Command-line Flag Parsing ---
	// Allow user to specify a config file path via a flag, e.g., --config=config-100.toml
	configFile := flag.String("config", "config.toml", "Path to the configuration file.")
	flag.Parse()

	// 1. Load configuration from the specified file
	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration from '%s'. Error: %v", *configFile, err)
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

	fmt.Printf("Starting check with %d domains and concurrency level of %d...\n", len(cfg.Settings.Domains), cfg.Settings.Concurrency)

	// Start timer for performance measurement
	startTime := time.Now()
	printMemUsage()


	// --- Worker Pool Implementation ---
	numJobs := len(cfg.Settings.Domains)
	jobs := make(chan string, numJobs)
	results := make(chan CheckResult, numJobs)

	var wg sync.WaitGroup
	numWorkers := cfg.Settings.Concurrency
	if numWorkers <= 0 {
		numWorkers = 8 // Default to 8 workers if not specified or invalid
	}

	// 2a. Start workers
	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobs {
				expiryDate, err := checker.CheckHost(domain)
				results <- CheckResult{Domain: domain, ExpiryDate: expiryDate, Err: err}
			}
		}()
	}

	// 2b. Send jobs to the jobs channel
	for _, domain := range cfg.Settings.Domains {
		jobs <- domain
	}
	close(jobs)

	// 2c. Wait for all workers to finish their jobs
	wg.Wait()
	close(results)
	// --- End Worker Pool ---

	// Stop timer and calculate duration
	duration := time.Since(startTime)
	printMemUsage()
	fmt.Printf("Total execution time: %s\n", duration)

	var foundAlerts bool

	// 3. Process all results collected from the workers
	for result := range results {
		if result.Err != nil {
			errorMessage := fmt.Sprintf("[ERROR] Could not check %s: %v", result.Domain, result.Err)
			fmt.Println(errorMessage)
			if slackNotifier != nil {
				_ = slackNotifier.Send(errorMessage)
			}
			foundAlerts = true
			continue
		}

		alertInfo := evaluator.Evaluate(result.Domain, result.ExpiryDate, cfg.Settings.AlertThresholds)

		if alertInfo.ShouldAlert {
			fmt.Println(alertInfo.Message)
			if slackNotifier != nil {
				err := slackNotifier.Send(alertInfo.Message)
				if err != nil {
					log.Printf("Failed to send slack notification for %s: %v", result.Domain, err)
				}
			}
			foundAlerts = true
		} else {
			// Optional: print OK status for verbosity.
			// fmt.Println(alertInfo.Message)
		}
	}

	if !foundAlerts {
		fmt.Println("All certificates are OK.")
	}

	// Print the final performance measurement
	fmt.Printf("\n--- Experiment Finished ---\n")
	fmt.Printf("Total execution time: %s\n", duration)
}