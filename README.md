# Cert-Monitor  cert-monitor

![Go Version](https://img.shields.io/badge/go-1.22+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

A simple, efficient, and automated tool for monitoring SSL/TLS certificate expiration. Cert-Monitor helps system administrators track certificate expiry dates across multiple websites and sends timely alerts before they expire, preventing service disruptions.

This project is a submission for the NT140: Network Security course.

## Features ✨

* **Certificate Expiry Checks**: Connects to a list of specified domains over port 443, fetches SSL/TLS certificate information, and extracts the expiration date.
* **Flexible Configuration**: Allows users to easily define a list of domains to monitor and set multiple warning thresholds (e.g., alert 30, 15, and 7 days before expiry) via a simple `config.toml` file.
* **Alerting**: Integrates with popular notification channels to send alerts. Currently supports:
    * Slack (via Incoming Webhooks)
* **Run as a Service**: Can be configured to run periodically (e.g., once a day) using standard system schedulers like `systemd timers` or `cron`.

## Installation ⚙️

### Prerequisites

* Go version 1.22 or newer.

### Build From Source

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/cert-monitor.git](https://github.com/your-username/cert-monitor.git)
    cd cert-monitor
    ```

2.  **Build the executable:**
    ```bash
    go build -o cert-monitor ./cmd/cert-monitor/main.go
    ```

3.  **Move the binary to a system path (optional but recommended):**
    ```bash
    sudo mv cert-monitor /usr/local/bin/
    ```

## Configuration ⚙️

Cert-Monitor is configured using a `config.toml` file. A sample configuration file is provided as `config.toml`.

1.  **Create your configuration file:**
    ```bash
    cp config.toml config.toml
    ```

2.  **Edit `config.toml`:**

    ```toml
    # config.toml - Main configuration file for Cert-Monitor

    [settings]
    # A list of domain names to monitor.
    domains = [
        "google.com",
        "github.com",
        "uit.edu.vn",
        "expired.badssl.com" 
    ]

    # Alert thresholds in days. An alert is sent when the days remaining
    # are less than or equal to one of these values.
    alert_thresholds = [30, 15, 7]

    [notifications.slack]
    # Enable or disable Slack notifications.
    enabled = true

    # The name of the environment variable that holds the Slack Webhook URL.
    # This is a security best practice to keep secrets out of the config file.
    webhook_url_env_var = "SLACK_WEBHOOK_URL"
    ```

3.  **Set up Environment Variables:**

    For security, sensitive information like the Slack Webhook URL is loaded from an environment variable.

    ```bash
    # Set this variable permanently in your shell profile (e.g., .bashrc, .zshrc)
    # or system-wide environment variables.
    export SLACK_WEBHOOK_URL="[https://hooks.slack.com/services/YOUR/WEBHOOK/URL](https://hooks.slack.com/services/YOUR/WEBHOOK/URL)"
    ```

## Usage 🚀

### Manual (One-off) Check

You can run the tool at any time to perform an immediate check:

```bash
cert-monitor