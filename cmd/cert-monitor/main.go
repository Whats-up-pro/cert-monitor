// File: cmd/cert-monitor/main.go
package main

import (
	"cert-monitor/internal/checker"
	"cert-monitor/internal/evaluator"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// Khai báo AlertThresholds (vì không đọc config.toml)
// Lưu ý: Giá trị [30, 7] giả định evaluator.Evaluate dùng []int và [0]=Warning, [1]=Critical
var serverAlertThresholds = []int{30, 7}

// Request struct để nhận tên miền từ Extension
type CertRequest struct {
	Domain string `json:"domain"`
}

// Response struct để gửi kết quả về Extension
type CertResponse struct {
	Message     string `json:"message"`
	ShouldAlert bool   `json:"json:"shouldAlert"`
	Error       string `json:"error,omitempty"`

	Issuer             string `json:"issuer"`
	ExpiryDate         string `json:"expiryDate"`
	DaysLeft           int    `json:"daysLeft"`
	PublicKeyType      string `json:"publicKeyType"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`
}

func checkCertHandler(w http.ResponseWriter, r *http.Request) {
	// Cấu hình CORS BẮT BUỘC cho Extension chạy Localhost
	startTime := time.Now()
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:8080")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON input", http.StatusBadRequest)
		return
	}
	domain := req.Domain

	checkStart := time.Now()
	certInfo, err := checker.CheckHost(domain)
	checkDuration := time.Since(checkStart)

	// 1. Kiểm tra Chứng chỉ
	if err != nil {
		resp := CertResponse{
			Message:     fmt.Sprintf("CRITICAL: Error checking %s", domain),
			ShouldAlert: true,
			Error:       err.Error(),
			DaysLeft:    -1,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	evalStart := time.Now()
	alertInfo := evaluator.Evaluate(domain, certInfo, serverAlertThresholds)
	evalDuration := time.Since(evalStart)

	// 2. Đánh giá
	resp := CertResponse{
		Message:            alertInfo.Message,
		ShouldAlert:        alertInfo.ShouldAlert,
		Issuer:             certInfo.Issuer,
		ExpiryDate:         certInfo.ExpiryDate.Format(time.RFC3339),
		DaysLeft:           alertInfo.DaysLeft,
		PublicKeyType:      certInfo.PublicKeyType,
		SignatureAlgorithm: certInfo.SignatureAlgorithm,
	}
	totalDuration := time.Since(startTime)
	log.Printf("[API Performance] DOMAIN: %s | CHECK: %s | EVAL: %s | TOTAL: %s",
		domain,
		checkDuration,
		evalDuration,
		totalDuration,
	)
	// 3. Gửi Response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {
	http.HandleFunc("/check-cert", checkCertHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Server API running at http://localhost:%s/check-cert\n", port)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
