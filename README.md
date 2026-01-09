# Cert-Monitor v2.0

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Go](https://img.shields.io/badge/go-1.22+-00ADD8.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**Advanced MITM Detection Framework with Multi-Dimensional Certificate Validation**

Cert-Monitor v2.0 is a hybrid cross-verification framework designed to detect sophisticated Man-in-the-Middle (MITM) attacks that bypass standard browser defenses, particularly Root CA injection attacks.

## 🆕 What's New in v2.0

| Feature | v1.0 | v2.0 |
|---------|------|------|
| Validation Approach | Single fingerprint | **Multi-Dimensional (7 dimensions)** |
| External Verification | Centralized Oracle | **Decentralized BFT Consensus** |
| Anomaly Detection | Rule-based | **ML-Powered Detection** |
| Performance | ~539ms latency | **Optimized with TOFU caching** |
| Security Proof | None | **Ed25519 Cryptographic Attestation** |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Cert-Monitor v2.0 Architecture                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐    ┌──────────────────────────────────┐   │
│  │ Browser Extension │───▶│    Verification Agent (Go)      │   │
│  │   (Manifest V3)   │    │  ┌────────────────────────────┐ │   │
│  │                   │    │  │ Multi-Dimensional Validator│ │   │
│  │  ├─ background.js │    │  ├─ Fingerprint Comparison   │ │   │
│  │  ├─ content.js    │    │  ├─ CT Log Verification     │ │   │
│  │  └─ popup/        │    │  ├─ OCSP Status Check       │ │   │
│  └──────────────────┘    │  ├─ Heuristic Analysis       │ │   │
│                           │  ├─ ML Anomaly Detection    │ │   │
│                           │  └─ TOFU Cache              │ │   │
│                           └──────────────────────────────────┘   │
│                                        │                         │
│                                        ▼                         │
│                           ┌──────────────────────────────────┐   │
│                           │    BFT Consensus Engine         │   │
│                           │  (Multi-Agent Verification)     │   │
│                           └──────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## 📋 Features

### Multi-Dimensional Validation
- **Fingerprint (30%)**: Split-View comparison between client and agent
- **CT Presence (25%)**: Certificate Transparency log verification
- **OCSP Status (15%)**: Real-time revocation checking
- **DNS CAA (10%)**: Certification Authority Authorization
- **Historical (10%)**: TOFU cache comparison
- **Chain Validity (5%)**: Certificate chain analysis
- **ML Anomaly (5%)**: Machine learning-based detection

### Security Innovations
- **Decentralized Consensus**: Byzantine Fault Tolerant verification
- **Cryptographic Attestation**: Ed25519 signed proofs
- **Zero Trust**: No implicit trust in local environment

### Performance Optimizations
- **TOFU Caching**: <10ms for cached domains
- **Parallel Validation**: Concurrent dimension checks
- **Goroutine Pool**: High-concurrency Go backend

## 🚀 Quick Start

### Prerequisites
- Go 1.22 or newer
- Chrome/Edge browser (for extension)

### Build the Agent

```bash
cd cert-monitor

# Download dependencies
go mod tidy

# Build the agent
go build -o cert-monitor-agent ./cmd/agent

# Run the agent
./cert-monitor-agent
```

### Build the CLI

```bash
go build -o cert-monitor-cli ./cmd/cli

# Verify a domain
./cert-monitor-cli verify -domain google.com

# Batch verify
./cert-monitor-cli batch -domains "google.com,github.com,cloudflare.com"
```

### Install the Extension

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `extension/` directory

## 📖 API Reference

### POST /api/v2/verify

Verify a single domain's certificate.

**Request:**
```json
{
  "domain": "google.com",
  "client_fingerprint": "abc123...", // optional
  "request_id": "req-123"
}
```

**Response:**
```json
{
  "verdict": "SAFE",
  "confidence": 0.95,
  "security_score": 87.5,
  "anomaly_score": 0.12,
  "dimensions": [
    {"dimension": "FINGERPRINT", "status": "PASS", "score": 1.0},
    {"dimension": "CT_PRESENCE", "status": "PASS", "score": 0.9}
  ],
  "latency_ms": 234
}
```

### POST /api/v2/batch-verify

Batch verify multiple domains.

### GET /api/v2/health

Health check endpoint.

### GET /api/v2/info

Agent information and capabilities.

## 🧪 Running Experiments

### MITM Detection Test

```bash
# 1. Start the agent
./cert-monitor-agent

# 2. Configure Burp Suite as proxy (127.0.0.1:8080)
# 3. Import PortSwigger CA into system trust store

# 4. Run detection test
./cert-monitor-cli verify -domain google.com
```

### Benchmark

```bash
# Run performance benchmark
./scripts/benchmark.sh
```

## 📊 Experimental Results

| Metric | Result |
|--------|--------|
| Detection Rate (MITM) | 100% |
| False Positive Rate | 0% |
| Average Latency (Cold) | ~400ms |
| Average Latency (Cached) | <10ms |
| CT Log Coverage | 90%+ |

## 🔧 Configuration

Edit `config.toml`:

```toml
[server]
port = 8080

[validator]
enable_fingerprint = true
enable_ct = true
enable_ocsp = true
enable_ml = true

[cache]
enable_tofu = true
ttl = "24h"
```

## 📁 Project Structure

```
cert-monitor/
├── cmd/
│   ├── agent/          # Verification Agent
│   └── cli/            # CLI Tool
├── internal/
│   ├── core/           # Core types and validator
│   ├── fetcher/        # TLS, CT, OCSP fetchers
│   ├── analyzer/       # Heuristic and ML analysis
│   ├── api/            # HTTP server
│   └── config/         # Configuration
├── extension/          # Chrome Extension
├── testdata/           # Test data
└── scripts/            # Utility scripts
```

## 📝 Research Contributions

1. **Multi-Dimensional Validation**: Beyond single fingerprint comparison
2. **Decentralized Consensus**: Eliminates single point of failure
3. **ML Anomaly Detection**: Intelligent certificate analysis
4. **Cryptographic Attestation**: Verifiable agent integrity
5. **Optimized TOFU**: Balance between security and performance

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

## 👥 Authors

- Nguyen Minh Quang Vu
- Quang Vu Phan  
- Tan-Gia-Quoc Pham
- Ngoc Toan Khuong
- Tuan-Dung Tran

University of Information Technology, VNU-HCM

---

**Cert-Monitor v2.0** - Protecting your encrypted connections beyond browser trust.