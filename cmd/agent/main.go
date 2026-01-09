// Cert-Monitor v2.0 - Verification Agent
// A hybrid cross-verification framework for detecting advanced MITM attacks
package main

import (
	"cert-monitor/internal/api"
	"cert-monitor/internal/config"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

const (
	Version = "2.0.0"
	Banner  = `
   ____          _       __  __             _ _             
  / ___|___ _ __| |_    |  \/  | ___  _ __ (_) |_ ___  _ __ 
 | |   / _ \ '__| __|   | |\/| |/ _ \| '_ \| | __/ _ \| '__|
 | |__|  __/ |  | |_    | |  | | (_) | | | | | || (_) | |   
  \____\___|_|   \__|   |_|  |_|\___/|_| |_|_|\__\___/|_|   
                                                             
  Advanced MITM Detection Framework v2.0
  Multi-Dimensional Validation | BFT Consensus | ML Anomaly Detection
`
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config.toml", "Path to configuration file")
	agentID := flag.String("agent-id", "", "Override agent ID from config")
	region := flag.String("region", "", "Override region from config")
	port := flag.Int("port", 0, "Override port from config")
	flag.Parse()

	// Print banner
	log.Print(Banner)
	log.Printf("Version: %s", Version)

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Apply command line overrides
	if *agentID != "" {
		cfg.Agent.ID = *agentID
	}
	if *region != "" {
		cfg.Agent.Region = *region
	}
	if *port > 0 {
		cfg.Server.Port = *port
	}

	// Set default agent ID if not set
	if cfg.Agent.ID == "" {
		hostname, _ := os.Hostname()
		cfg.Agent.ID = "agent-" + hostname
	}

	// Create and start server
	server := api.NewServer(cfg)

	// Handle graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("Shutting down gracefully...")
		os.Exit(0)
	}()

	// Start server
	if err := server.Start(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
