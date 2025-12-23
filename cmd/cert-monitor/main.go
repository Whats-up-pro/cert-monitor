// File: cmd/cert-monitor/main.go
package main

import (
	"cert-monitor/internal/checker"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
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
	Fingerprints       []string `json:"fingerprints"`
	SecurityScore      int      `json:"security_score"`
	RiskLevel          string   `json:"risk_level"`
	ProcessTimeMs      int64    `json:"process_time_ms"`
	ShouldAlert        bool     `json:"shouldAlert"`
	Error              string   `json:"error,omitempty"`
}

// Hàm hỗ trợ lấy IP thực của Client
// Ưu tiên X-Forwarded-For (nếu chạy sau Proxy/Cloudflare), fallback về RemoteAddr
func getRealClientIP(r *http.Request) string {
	// 1. Check Header X-Forwarded-For (Chuẩn cho Proxy)
	xfwd := r.Header.Get("X-Forwarded-For")
	if xfwd != "" {
		// Header này có dạng: "client_ip, proxy1, proxy2"
		// Chúng ta chỉ cần lấy IP đầu tiên (client thật)
		ips := strings.Split(xfwd, ",")
		return strings.TrimSpace(ips[0])
	}

	// 2. Check Header X-Real-Ip (Một số proxy dùng cái này)
	xreal := r.Header.Get("X-Real-Ip")
	if xreal != "" {
		return xreal
	}

	// 3. Fallback: Lấy trực tiếp từ kết nối
	// RemoteAddr có dạng "IP:Port" (vd: 127.0.0.1:54321), cần tách Port ra
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // Nếu lỗi format, trả về nguyên gốc
	}
	return host
}

func checkCertHandler(w http.ResponseWriter, r *http.Request) {
	// CORS Headers
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

	// --- LOGIC MỚI BẮT ĐẦU TỪ ĐÂY ---
	
	// 1. Lấy IP của người dùng để phục vụ tính năng ECS (Geo-DNS)
	clientIP := getRealClientIP(r)

	log.Printf("Checking: %s (Client IP detected: %s)", req.Domain, clientIP)
	
	// 2. Gọi Checker với 2 tham số: Domain và ClientIP
	certInfo, err := checker.CheckHost(req.Domain, clientIP)

	// --- KẾT THÚC LOGIC MỚI ---

	resp := CertResponse{}

	if err != nil {
		log.Printf("Error checking %s: %v", req.Domain, err)
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
	
	fmt.Printf("🛡️  Cert-Monitor Hybrid Agent (ECS/Geo-DNS Enabled) running at :%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}