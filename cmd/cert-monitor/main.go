// File: cmd/cert-monitor/main.go
package main

import (
	"cert-monitor/internal/checker"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// Request từ Extension
type CertRequest struct {
	Domain string `json:"domain"`
}

// Response trả về Extension
type CertResponse struct {
	Issuer             string `json:"issuer"`
	ExpiryDate         string `json:"expiryDate"`
	DaysLeft           int    `json:"daysLeft"`
	PublicKeyType      string `json:"publicKeyType"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`
	Fingerprint   string `json:"fingerprint"`    // Vân tay SHA-256
	SecurityScore int    `json:"security_score"` // Điểm số (0-100)
	RiskLevel     string `json:"risk_level"`     // SAFE, WARNING, CRITICAL

	ShouldAlert bool   `json:"shouldAlert"`
	Error       string `json:"error,omitempty"`
}

func checkCertHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Cấu hình CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Xử lý Preflight request
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 2. Đọc Request
	var req CertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON input", http.StatusBadRequest)
		return
	}

	log.Printf("Checking domain: %s", req.Domain)
	
	// 3. Gọi Checker (Logic trung tâm)
	certInfo, err := checker.CheckHost(req.Domain)

	resp := CertResponse{}

	// 4. Xử lý kết quả
	if err != nil {
		log.Printf("Error checking %s: %v", req.Domain, err)
		resp.ShouldAlert = true
		resp.Error = err.Error()
		resp.DaysLeft = -1
		resp.RiskLevel = "CRITICAL"
		resp.SecurityScore = 0
	} else {
		// Map dữ liệu từ Checker sang Response JSON
		resp.Issuer = certInfo.Issuer
		resp.ExpiryDate = certInfo.ExpiryDate.Format(time.RFC3339)
		resp.DaysLeft = certInfo.DaysLeft
		resp.PublicKeyType = certInfo.PublicKeyType
		resp.SignatureAlgorithm = certInfo.SignatureAlgorithm
		
		// Map các trường mới
		resp.Fingerprint = certInfo.Fingerprint
		resp.SecurityScore = certInfo.SecurityScore
		resp.RiskLevel = certInfo.RiskLevel

		// Logic cảnh báo đơn giản dựa trên RiskLevel từ Checker
		if certInfo.RiskLevel != "SAFE" {
			resp.ShouldAlert = true
		}
	}

	// 5. Trả về JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func main() {
	http.HandleFunc("/check-cert", checkCertHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("🛡️  Cert-Monitor Hybrid Agent running at http://localhost:%s/check-cert\n", port)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}