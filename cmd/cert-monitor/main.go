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

type CertRequest struct {
	Domain string `json:"domain"`
}

type CertResponse struct {
	Issuer             string   `json:"issuer"`
	ExpiryDate         string   `json:"expiryDate"`
	DaysLeft           int      `json:"daysLeft"`
	PublicKeyType      string   `json:"publicKeyType"`
	SignatureAlgorithm string   `json:"signatureAlgorithm"`
	
	// Thay đổi: Trả về danh sách fingerprint
	Fingerprints       []string `json:"fingerprints"` 
	
	SecurityScore      int      `json:"security_score"`
	RiskLevel          string   `json:"risk_level"`
	ProcessTimeMs      int64    `json:"process_time_ms"` // Thêm thời gian xử lý để đo đạc

	ShouldAlert        bool     `json:"shouldAlert"`
	Error              string   `json:"error,omitempty"`
}

func checkCertHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req CertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	log.Printf("Checking: %s", req.Domain)
	
	// Gọi Checker mới (Multi-IP)
	certInfo, err := checker.CheckHost(req.Domain)

	resp := CertResponse{}

	if err != nil {
		log.Printf("Error %s: %v", req.Domain, err)
		resp.ShouldAlert = true
		resp.Error = err.Error()
		resp.DaysLeft = -1
		resp.RiskLevel = "CRITICAL"
	} else {
		resp.Issuer = certInfo.Issuer
		resp.ExpiryDate = certInfo.ExpiryDate.Format(time.RFC3339)
		resp.DaysLeft = certInfo.DaysLeft
		resp.PublicKeyType = certInfo.PublicKeyType
		resp.SignatureAlgorithm = certInfo.SignatureAlgorithm
		
		// Trả về danh sách Fingerprints
		resp.Fingerprints = certInfo.ValidFingerprints
		
		resp.SecurityScore = certInfo.SecurityScore
		resp.RiskLevel = certInfo.RiskLevel
		resp.ProcessTimeMs = certInfo.CheckDuration.Milliseconds()

		if certInfo.RiskLevel != "SAFE" {
			resp.ShouldAlert = true
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {
	http.HandleFunc("/check-cert", checkCertHandler)
	port := os.Getenv("PORT")
	if port == "" { port = "8080" }
	fmt.Printf("🛡️  Cert-Monitor Hybrid Agent (Multi-IP Aware) running at :%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}