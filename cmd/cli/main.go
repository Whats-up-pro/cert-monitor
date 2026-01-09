// Cert-Monitor CLI - Command-line testing tool
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	Version = "2.0.0"
	DefaultAgentURL = "http://localhost:8080"
)

func main() {
	// Subcommands
	verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)
	batchCmd := flag.NewFlagSet("batch", flag.ExitOnError)
	healthCmd := flag.NewFlagSet("health", flag.ExitOnError)
	infoCmd := flag.NewFlagSet("info", flag.ExitOnError)

	// Verify flags
	verifyDomain := verifyCmd.String("domain", "", "Domain to verify")
	verifyFingerprint := verifyCmd.String("fp", "", "Client certificate fingerprint (optional)")
	verifyAgent := verifyCmd.String("agent", DefaultAgentURL, "Agent URL")
	verifyJSON := verifyCmd.Bool("json", false, "Output as JSON")

	// Batch flags
	batchDomains := batchCmd.String("domains", "", "Comma-separated list of domains")
	batchFile := batchCmd.String("file", "", "File with domains (one per line)")
	batchAgent := batchCmd.String("agent", DefaultAgentURL, "Agent URL")

	// Health flags
	healthAgent := healthCmd.String("agent", DefaultAgentURL, "Agent URL")

	// Info flags
	infoAgent := infoCmd.String("agent", DefaultAgentURL, "Agent URL")

	// Check for subcommand
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "verify":
		verifyCmd.Parse(os.Args[2:])
		if *verifyDomain == "" {
			fmt.Println("Error: -domain is required")
			os.Exit(1)
		}
		runVerify(*verifyAgent, *verifyDomain, *verifyFingerprint, *verifyJSON)

	case "batch":
		batchCmd.Parse(os.Args[2:])
		var domains []string
		if *batchDomains != "" {
			domains = strings.Split(*batchDomains, ",")
		} else if *batchFile != "" {
			domains = loadDomainsFromFile(*batchFile)
		} else {
			fmt.Println("Error: -domains or -file is required")
			os.Exit(1)
		}
		runBatch(*batchAgent, domains)

	case "health":
		healthCmd.Parse(os.Args[2:])
		runHealth(*healthAgent)

	case "info":
		infoCmd.Parse(os.Args[2:])
		runInfo(*infoAgent)

	case "version":
		fmt.Printf("Cert-Monitor CLI v%s\n", Version)

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Cert-Monitor CLI v2.0 - Certificate Verification Tool

Usage:
  cert-monitor-cli <command> [options]

Commands:
  verify    Verify a single domain
  batch     Verify multiple domains
  health    Check agent health
  info      Get agent information
  version   Print version

Examples:
  cert-monitor-cli verify -domain google.com
  cert-monitor-cli verify -domain google.com -fp abc123
  cert-monitor-cli batch -domains "google.com,github.com,cloudflare.com"
  cert-monitor-cli batch -file domains.txt
  cert-monitor-cli health
`)
}

func runVerify(agentURL, domain, fingerprint string, jsonOutput bool) {
	fmt.Printf("🔍 Verifying: %s\n", domain)
	fmt.Printf("📡 Agent: %s\n\n", agentURL)

	// Build request
	reqBody := map[string]interface{}{
		"domain":    domain,
		"request_id": fmt.Sprintf("cli-%d", time.Now().UnixNano()),
		"timestamp": time.Now().Unix(),
	}
	if fingerprint != "" {
		reqBody["client_fingerprint"] = fingerprint
	}

	body, _ := json.Marshal(reqBody)
	resp, err := http.Post(agentURL+"/api/v2/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if jsonOutput {
		var prettyJSON bytes.Buffer
		json.Indent(&prettyJSON, respBody, "", "  ")
		fmt.Println(prettyJSON.String())
		return
	}

	// Parse and display friendly output
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)

	verdict := result["verdict"].(string)
	score := result["security_score"].(float64)
	latency := result["latency_ms"].(float64)
	message := result["message"].(string)

	// Verdict emoji
	var verdictEmoji string
	switch verdict {
	case "SAFE":
		verdictEmoji = "✅"
	case "MITM_DETECTED":
		verdictEmoji = "🚨"
	case "SUSPICIOUS":
		verdictEmoji = "⚠️"
	default:
		verdictEmoji = "❓"
	}

	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("%s Verdict: %s\n", verdictEmoji, verdict)
	fmt.Printf("📊 Security Score: %.1f/100\n", score)
	fmt.Printf("⏱️  Latency: %.0fms\n", latency)
	fmt.Printf("💬 %s\n", message)
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	// Show dimensions
	if dims, ok := result["dimensions"].([]interface{}); ok {
		fmt.Println("\n📋 Validation Dimensions:")
		for _, d := range dims {
			dim := d.(map[string]interface{})
			name := dim["dimension"].(string)
			status := dim["status"].(string)
			dimScore := dim["score"].(float64)
			details := dim["details"].(string)

			var statusEmoji string
			switch status {
			case "PASS":
				statusEmoji = "✓"
			case "FAIL":
				statusEmoji = "✗"
			case "WARNING":
				statusEmoji = "!"
			default:
				statusEmoji = "?"
			}

			fmt.Printf("  %s [%.0f%%] %s: %s\n", statusEmoji, dimScore*100, name, details)
		}
	}
}

func runBatch(agentURL string, domains []string) {
	fmt.Printf("🔍 Batch verifying %d domains\n", len(domains))
	fmt.Printf("📡 Agent: %s\n\n", agentURL)

	reqBody := map[string]interface{}{
		"domains": domains,
	}

	body, _ := json.Marshal(reqBody)
	resp, err := http.Post(agentURL+"/api/v2/batch-verify", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	var result map[string]interface{}
	json.Unmarshal(respBody, &result)

	summary := result["summary"].(map[string]interface{})
	totalTime := result["total_time_ms"].(float64)

	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("📊 Summary:\n")
	fmt.Printf("   Total: %.0f\n", summary["total"].(float64))
	fmt.Printf("   ✅ Safe: %.0f\n", summary["safe"].(float64))
	fmt.Printf("   🚨 MITM: %.0f\n", summary["mitm_detected"].(float64))
	fmt.Printf("   ⚠️  Suspicious: %.0f\n", summary["suspicious"].(float64))
	fmt.Printf("   ❌ Errors: %.0f\n", summary["errors"].(float64))
	fmt.Printf("   ⏱️  Time: %.0fms\n", totalTime)
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	// Show individual results
	if results, ok := result["results"].(map[string]interface{}); ok {
		fmt.Println("\n📋 Individual Results:")
		for domain, r := range results {
			res := r.(map[string]interface{})
			verdict := res["verdict"].(string)
			score := res["security_score"].(float64)

			var emoji string
			switch verdict {
			case "SAFE":
				emoji = "✅"
			case "MITM_DETECTED":
				emoji = "🚨"
			case "SUSPICIOUS":
				emoji = "⚠️"
			default:
				emoji = "❓"
			}

			fmt.Printf("  %s %s: %s (%.0f%%)\n", emoji, domain, verdict, score)
		}
	}
}

func runHealth(agentURL string) {
	fmt.Printf("🏥 Checking health: %s\n\n", agentURL)

	resp, err := http.Get(agentURL + "/api/v2/health")
	if err != nil {
		fmt.Printf("❌ Agent unreachable: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result map[string]interface{}
	json.Unmarshal(body, &result)

	status := result["status"].(string)
	agentID := result["agent_id"].(string)
	region := result["region"].(string)
	version := result["version"].(string)

	statusEmoji := "✅"
	if status != "healthy" {
		statusEmoji = "❌"
	}

	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("%s Status: %s\n", statusEmoji, status)
	fmt.Printf("🆔 Agent ID: %s\n", agentID)
	fmt.Printf("🌍 Region: %s\n", region)
	fmt.Printf("📦 Version: %s\n", version)
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	// Show peer health if available
	if peerHealth, ok := result["peer_health"].(map[string]interface{}); ok {
		fmt.Println("\n🔗 Peer Health:")
		for peer, healthy := range peerHealth {
			emoji := "✅"
			if !healthy.(bool) {
				emoji = "❌"
			}
			fmt.Printf("  %s %s\n", emoji, peer)
		}
	}
}

func runInfo(agentURL string) {
	fmt.Printf("ℹ️  Agent info: %s\n\n", agentURL)

	resp, err := http.Get(agentURL + "/api/v2/info")
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var prettyJSON bytes.Buffer
	json.Indent(&prettyJSON, body, "", "  ")
	fmt.Println(prettyJSON.String())
}

func loadDomainsFromFile(path string) []string {
	content, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("❌ Error reading file: %v\n", err)
		os.Exit(1)
	}

	lines := strings.Split(string(content), "\n")
	var domains []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}
	return domains
}
