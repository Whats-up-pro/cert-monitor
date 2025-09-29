// File: internal/config/config.go
package config

import (
	"github.com/BurntSushi/toml"
)

// Config struct to match the structure of the config.toml file.
type Config struct {
	Settings      Settings      `toml:"settings"`
	Notifications Notifications `toml:"notifications"`
}

// Settings struct holds all the configurable parameters.
type Settings struct {
	Domains         []string `toml:"domains"`
	AlertThresholds []int    `toml:"alert_thresholds"`
}

// Notifications struct holds configuration for all notification channels.
type Notifications struct {
	Slack SlackConfig `toml:"slack"`
}

// SlackConfig holds configuration specific to Slack notifications.
type SlackConfig struct {
	Enabled          bool   `toml:"enabled"`
	WebhookURLEnvVar string `toml:"webhook_url_env_var"`
}

// Load loads configuration from a given file path.
func Load(filePath string) (*Config, error) {
	var config Config
	if _, err := toml.DecodeFile(filePath, &config); err != nil {
		return nil, err
	}
	return &config, nil
}