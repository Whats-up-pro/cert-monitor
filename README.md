# Cert-Monitor: Hybrid MITM Detection System

![Go Version](https://img.shields.io/badge/go-1.22+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Chrome%20Extension%20%7C%20Windows-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**Cert-Monitor** is a real-time Man-in-the-Middle (MITM) detection system designed for browsers. It utilizes a hybrid architecture combining a **Chrome Extension**, a **Native Messaging Host**, and a **Backend Analysis Server** to cross-verify SSL/TLS certificate integrity.

Course Project: **NT140 - Network Security**.

## 🚀 Key Features

* **Hybrid Verification:** Cross-references certificate fingerprints from three distinct perspectives to eliminate blind spots:
    1.  **Browser View:** The certificate seen by the browser user.
    2.  **Native OS View:** The certificate fetched directly from the OS store (bypassing browser hooks via Native Host).
    3.  **Global View:** The actual certificate seen by an external, independent Analysis Agent.
* **Strict Mode:** Active protection that blocks connections and alerts the user immediately upon detecting fingerprint mismatches or high-risk indicators.
* **Trust On First Use (TOFU):** Intelligent verification mechanism that builds a whitelist of trusted fingerprints based on safe browsing history.
* **Real-time Scoring:** Dynamically calculates a security score for visited HTTPS websites based on risk analysis algorithms.

## 🏗 Architecture

The system consists of three main components:

1.  **Chrome Extension (`/`):** The user interface that monitors navigation, intercepts risky requests, and displays security insights.
2.  **Native Host (`cert-monitor-native/`):** A background Go application acting as a bridge to the Operating System, allowing the extension to inspect raw certificates bypassing potential browser-level tampering.
3.  **Analysis Server (`cmd/cert-monitor/`):** An external API Server (Go) that provides a "clean" view of the target website's certificate from outside the local network.

## 🛠 Installation & Usage

### Prerequisites
* Go 1.22 or newer.
* Google Chrome (Developer Mode enabled).
* Windows OS (Required for the Native Host `.exe`).

### Step 1: Start the Backend Server
The server acts as the external "Agent" to verify certificates.

```bash
cd cmd/cert-monitor
go run main.go
# Server will start at http://localhost:8080


Step 2: Install the Native Host
This component enables communication between Chrome and the OS.

Navigate to cert-monitor-native/.

Build the executable (if not already built):

Bash

go build -o cert-native.exe main.go
Run install.bat as Administrator. This registers the Native Host manifest with the Windows Registry so Chrome can find it.

Step 3: Load the Chrome Extension
Open Chrome and navigate to chrome://extensions/.

Enable Developer mode (top right corner).

Click Load unpacked and select the root cert-monitor/ directory.

Pin the extension icon to your toolbar for easy access.

⚙️ Configuration
Server Config: Edit config.toml to manage the monitoring port and periodic domain checks.

Extension Config: Toggle Strict Mode directly via the Extension Popup interface.

📂 Project Structure
cert-monitor/
├── cert-monitor-native/    # Native Messaging Host (Go code + Installer)
├── cmd/                    # Backend Server & Experiments
├── internal/               # Core logic modules (Checker, Notifier, etc.)
├── background.js           # Extension Service Worker (Central logic)
├── checking.js             # Logic for the Blocking/Warning page
├── popup.js                # Popup UI logic
└── manifest.json           # Chrome Extension Manifest
📝 License
Distributed under the MIT License.



git add .

# 3. Commit với nội dung cập nhật tài liệu
git commit -m "docs: update README to English and remove junk files"