# TrustGuard: MITM Detection with Decentralized Multi-Vantage Trust Consensus

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Go](https://img.shields.io/badge/go-1.22+-00ADD8.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**Split-View Certificate Verification with Multi-Dimensional Validation**

TrustGuard is a detection framework for client-side TLS interception attacks based on the split-view principle: comparing locally observed certificates against those seen by external verification agents.

## 🔬 Key Features

| Feature | Description |
|---------|-------------|
| **Split-View Detection** | Detects certificate discrepancies between client and external vantage points |
| **DMTC Protocol** | Decentralized Multi-Vantage Trust Consensus with diversity constraints |
| **Multi-Dimensional Scoring** | 5 active validation dimensions with configurable weights |
| **Native Messaging** | Bypasses browser sandbox for ground-truth certificate extraction |
| **BFT Consensus** | Optional Byzantine Fault Tolerant multi-agent verification |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      TrustGuard Architecture                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐    ┌──────────────────────────────────┐   │
│  │ Browser Extension │───▶│    Native Host (Go)              │   │
│  │   (Manifest V3)   │    │    Certificate Extraction        │   │
│  └──────────────────┘    └──────────────┬───────────────────┘   │
│                                          │                       │
│                                          ▼                       │
│                           ┌──────────────────────────────────┐   │
│                           │    Verification Agent (Go)       │   │
│                           │  ┌────────────────────────────┐  │   │
│                           │  │ Multi-Dimensional Validator │  │   │
│                           │  │ • Fingerprint (30%)        │  │   │
│                           │  │ • CT Presence (25%)        │  │   │
│                           │  │ • OCSP Status (15%)        │  │   │
│                           │  │ • Historical/TOFU (10%)    │  │   │
│                           │  │ • Chain Heuristics (10%)   │  │   │
│                           │  │ • Statistical Anomaly (10%)│  │   │
│                           │  └────────────────────────────┘  │   │
│                           └──────────────┬───────────────────┘   │
│                                          │                       │
│                                          ▼                       │
│                           ┌──────────────────────────────────┐   │
│                           │    DMTC Consensus Engine         │   │
│                           │  • Diversity constraints         │   │
│                           │  • BFT voting (67% threshold)   │   │
│                           │  • Ed25519 attestation          │   │
│                           └──────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## 📊 Experimental Results

| Metric | Result |
|--------|--------|
| Detection Accuracy | 99.3% (447/450) |
| False Positive Rate | 0.5% |
| Median Latency (Cold) | 387ms |
| Median Latency (Cached) | 8ms |
| Multi-Agent (5, parallel) | 448ms |

## 🚀 Quick Start

### Prerequisites
- Go 1.22+
- Google Chrome (Developer Mode)
- Windows OS (for Native Host)

### Build & Run

```bash
# Clone and build
cd cert-monitor
go mod tidy

# Build agent
go build -o cert-monitor-agent.exe ./cmd/agent

# Build CLI
go build -o cert-monitor-cli.exe ./cmd/cli

# Run agent
./cert-monitor-agent.exe
```

### CLI Usage

```bash
# Verify single domain
./cert-monitor-cli verify -domain google.com

# Batch verify
./cert-monitor-cli batch -domains "google.com,github.com"
```

### Install Extension
1. Open `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked" → select `extension/` folder

## 📁 Project Structure

```
cert-monitor/
├── cmd/
│   ├── agent/              # Verification Agent server
│   └── cli/                # Command-line tool
├── internal/
│   ├── core/               # Validator, types, consensus
│   ├── dmtc/               # DMTC: types, registry, selector, consensus
│   ├── fetcher/            # TLS, CT, OCSP fetchers
│   ├── analyzer/           # Heuristic analysis
│   ├── api/                # HTTP server
│   └── config/             # Configuration
├── extension/              # Chrome Extension (Manifest V3)
├── cert-monitor-native/    # Native Messaging Host
└── config.toml             # Configuration file
```

## 🔧 Configuration

Key parameters in `config.toml`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `enable_fingerprint` | true | Enable fingerprint comparison |
| `enable_ct` | true | Enable CT log verification |
| `enable_ocsp` | true | Enable OCSP checking |
| `enable_consensus` | false | Enable multi-agent DMTC |
| `consensus_threshold` | 0.67 | BFT agreement threshold |
| `mitm_threshold` | 0.30 | Score threshold for MITM verdict |
| `cache_ttl` | 24h | TOFU cache lifetime |

## 📖 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v2/verify` | POST | Single domain verification |
| `/api/v2/batch-verify` | POST | Batch verification |
| `/verify-consensus` | POST | DMTC consensus verification |
| `/api/v2/health` | GET | Health check |

## 📝 Research

This project accompanies the paper:

> **TrustGuard: Split-View Certificate Verification with Decentralized Multi-Vantage Trust Consensus**
> 
> Detects Root CA injection attacks through split-view analysis and multi-dimensional validation.

Key contributions:
1. **DMTC Protocol**: Decentralized verification with diversity constraints (≥3 ASNs, ≥2 countries)
2. **Multi-Dimensional Scoring**: Beyond fingerprint comparison
3. **Geo-Targeted Attack Detection**: Leveraging network diversity

## 👥 Authors

- Nguyen Minh Quang Vu
- Quang Vu Phan
- Tan-Gia-Quoc Pham
- Ngoc Toan Khuong
- Tuan-Dung Tran (Corresponding)

University of Information Technology, VNU-HCM

## 📄 License

MIT License

---

**TrustGuard** - Detecting MITM attacks beyond browser trust.