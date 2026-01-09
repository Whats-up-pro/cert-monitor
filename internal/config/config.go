// Package config provides configuration management for Cert-Monitor
package config

import (
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// Config holds the complete application configuration
type Config struct {
	Server    ServerConfig    `toml:"server"`
	Agent     AgentConfig     `toml:"agent"`
	Validator ValidatorConfig `toml:"validator"`
	Cache     CacheConfig     `toml:"cache"`
	Logging   LoggingConfig   `toml:"logging"`
	Notifier  NotifierConfig  `toml:"notifier"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Host         string        `toml:"host"`
	Port         int           `toml:"port"`
	ReadTimeout  time.Duration `toml:"read_timeout"`
	WriteTimeout time.Duration `toml:"write_timeout"`
	EnableCORS   bool          `toml:"enable_cors"`
	TLSCertFile  string        `toml:"tls_cert_file"`
	TLSKeyFile   string        `toml:"tls_key_file"`
}

// AgentConfig holds verification agent configuration
type AgentConfig struct {
	ID          string   `toml:"id"`
	Region      string   `toml:"region"`
	PeerAgents  []string `toml:"peer_agents"`
	EnableConsensus bool `toml:"enable_consensus"`
	ConsensusThreshold float64 `toml:"consensus_threshold"`
}

// ValidatorConfig holds validation configuration
type ValidatorConfig struct {
	EnableFingerprint   bool          `toml:"enable_fingerprint"`
	EnableCT            bool          `toml:"enable_ct"`
	EnableOCSP          bool          `toml:"enable_ocsp"`
	EnableDNSCAA        bool          `toml:"enable_dns_caa"`
	EnableHistorical    bool          `toml:"enable_historical"`
	EnableML            bool          `toml:"enable_ml"`
	TotalTimeout        time.Duration `toml:"total_timeout"`
	PerCheckTimeout     time.Duration `toml:"per_check_timeout"`
	MITMThreshold       float64       `toml:"mitm_threshold"`
	SuspiciousThreshold float64       `toml:"suspicious_threshold"`
	AllowCDNVariance    bool          `toml:"allow_cdn_variance"`
}

// CacheConfig holds caching configuration
type CacheConfig struct {
	EnableTOFU  bool          `toml:"enable_tofu"`
	TTL         time.Duration `toml:"ttl"`
	MaxEntries  int           `toml:"max_entries"`
	PersistPath string        `toml:"persist_path"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level      string `toml:"level"`
	Format     string `toml:"format"` // "json" or "text"
	OutputPath string `toml:"output_path"`
}

// NotifierConfig holds notification configuration
type NotifierConfig struct {
	Slack   SlackConfig   `toml:"slack"`
	Webhook WebhookConfig `toml:"webhook"`
	Email   EmailConfig   `toml:"email"`
}

// SlackConfig holds Slack notification settings
type SlackConfig struct {
	Enabled          bool   `toml:"enabled"`
	WebhookURLEnvVar string `toml:"webhook_url_env_var"`
}

// WebhookConfig holds generic webhook settings
type WebhookConfig struct {
	Enabled bool   `toml:"enabled"`
	URL     string `toml:"url"`
	Secret  string `toml:"secret"`
}

// EmailConfig holds email notification settings
type EmailConfig struct {
	Enabled    bool     `toml:"enabled"`
	SMTPServer string   `toml:"smtp_server"`
	SMTPPort   int      `toml:"smtp_port"`
	Username   string   `toml:"username"`
	Password   string   `toml:"password"`
	From       string   `toml:"from"`
	To         []string `toml:"to"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         8080,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			EnableCORS:   true,
		},
		Agent: AgentConfig{
			ID:              "agent-default",
			Region:          "local",
			EnableConsensus: false,
			ConsensusThreshold: 0.67,
		},
		Validator: ValidatorConfig{
			EnableFingerprint:   true,
			EnableCT:            true,
			EnableOCSP:          true,
			EnableDNSCAA:        false,
			EnableHistorical:    true,
			EnableML:            true,
			TotalTimeout:        30 * time.Second,
			PerCheckTimeout:     10 * time.Second,
			MITMThreshold:       0.3,
			SuspiciousThreshold: 0.6,
			AllowCDNVariance:    true,
		},
		Cache: CacheConfig{
			EnableTOFU:  true,
			TTL:         24 * time.Hour,
			MaxEntries:  10000,
			PersistPath: "./cache.json",
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			OutputPath: "stdout",
		},
		Notifier: NotifierConfig{
			Slack: SlackConfig{
				Enabled:          false,
				WebhookURLEnvVar: "SLACK_WEBHOOK_URL",
			},
		},
	}
}

// Load loads configuration from a TOML file
func Load(path string) (*Config, error) {
	config := DefaultConfig()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return config, nil // Return defaults if file doesn't exist
	}

	if _, err := toml.DecodeFile(path, config); err != nil {
		return nil, err
	}

	return config, nil
}

// Save saves configuration to a TOML file
func (c *Config) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := toml.NewEncoder(f)
	return encoder.Encode(c)
}

// GetSlackWebhookURL retrieves Slack webhook URL from environment
func (c *Config) GetSlackWebhookURL() string {
	if c.Notifier.Slack.WebhookURLEnvVar != "" {
		return os.Getenv(c.Notifier.Slack.WebhookURLEnvVar)
	}
	return ""
}
