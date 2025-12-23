// File: cmd/experiment/main.go
package main

import (
	"cert-monitor/internal/checker"
	"crypto/sha256"
	"crypto/tls"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const WORKERS = 10 // Số luồng chạy song song

// Hàm lấy Public IP của máy đang chạy (để phục vụ ECS)
func getPublicIP() string {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		fmt.Println("⚠️ Warning: Could not get public IP. ECS might not work optimally.")
		return ""
	}
	defer resp.Body.Close()
	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(ip)
}

func main() {
	// 0. Lấy Public IP hiện tại để giả lập Client
	fmt.Println("⏳ Getting public IP for ECS simulation...")
	myIP := getPublicIP()
	fmt.Printf("✅ Current Client IP: %s\n", myIP)

	// 1. Đọc file Input
	inputFile, err := os.Open("top-1k.csv")
	if err != nil {
		log.Fatal("Lỗi mở file input (đảm bảo file top-1k.csv nằm cùng cấp go.mod):", err)
	}
	defer inputFile.Close()

	records, err := csv.NewReader(inputFile).ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	// 2. Tạo file Output
	outputFile, err := os.Create("results_fp_analysis.csv")
	if err != nil {
		log.Fatal(err)
	}
	defer outputFile.Close()

	writer := csv.NewWriter(outputFile)
	defer writer.Flush()

	// Header
	writer.Write([]string{
		"Rank", "Domain", "Status",
		"Agent_IPs_Found", "Agent_Latency_ms",
		"Local_Fingerprint", "Match_Found",
		"Is_False_Positive",
		"Error",
	})

	jobs := make(chan []string, len(records))
	results := make(chan []string, len(records))
	var wg sync.WaitGroup

	// Start Workers
	for w := 0; w < WORKERS; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for record := range jobs {
				if len(record) < 2 { continue }
				rank := record[0]
				domain := record[1]

				// --- BƯỚC 1: GIẢ LẬP CLIENT (LOCAL) ---
				localFP, localErr := getLocalFingerprint(domain)

				// --- BƯỚC 2: GIẢ LẬP SERVER AGENT (REMOTE) ---
				// QUAN TRỌNG: Truyền myIP vào để kích hoạt ECS
				agentInfo, agentErr := checker.CheckHost(domain, myIP)

				// --- BƯỚC 3: PHÂN TÍCH KẾT QUẢ ---
				var row []string

				if localErr != nil || agentErr != nil {
					errStr := ""
					if localErr != nil {
						errStr += fmt.Sprintf("[Local: %v] ", localErr)
					}
					if agentErr != nil {
						errStr += fmt.Sprintf("[Agent: %v]", agentErr)
					}
					// Ghi lại lỗi để phân tích (DNS vs Timeout)
					row = []string{rank, domain, "ERROR", "0", "0", "", "FALSE", "FALSE", errStr}
				} else {
					// So sánh: Local Fingerprint có nằm trong danh sách Agent tìm được không?
					isMatch := false
					for _, remoteFP := range agentInfo.ValidFingerprints {
						if strings.EqualFold(localFP, remoteFP) { // So sánh không phân biệt hoa thường
							isMatch = true
							break
						}
					}

					// Đánh giá False Positive
					isFP := "FALSE"
					status := "SAFE"

					if !isMatch {
						isFP = "TRUE" // False Positive do CDN (nếu ECS không hoạt động tốt)
						status = "MISMATCH"
					}

					row = []string{
						rank,
						domain,
						status,
						fmt.Sprintf("%d", len(agentInfo.ValidFingerprints)),
						fmt.Sprintf("%d", agentInfo.CheckDuration.Milliseconds()),
						localFP[:8] + "...",
						fmt.Sprintf("%v", isMatch),
						isFP,
						"",
					}
				}

				results <- row
				
				// Log gọn gàng ra màn hình
				logMsg := fmt.Sprintf("[%s] %s", rank, domain)
				if row[2] == "ERROR" {
					fmt.Printf("%s -> ❌ ERROR\n", logMsg)
				} else if row[2] == "MISMATCH" {
					fmt.Printf("%s -> ⚠️ MISMATCH (Possible FP)\n", logMsg)
				} else {
					fmt.Printf("%s -> ✅ SAFE (%dms)\n", logMsg, agentInfo.CheckDuration.Milliseconds())
				}
			}
		}()
	}

	for _, rec := range records {
		jobs <- rec
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		writer.Write(r)
	}
	fmt.Println("Done! Results saved to results_fp_analysis.csv")
}

// Hàm giả lập Client kết nối đơn giản
func getLocalFingerprint(domain string) (string, error) {
	if !strings.Contains(domain, ":") {
		domain += ":443"
	}
	// Timeout 5s cho Client
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", domain, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("no certs")
	}
	
	hash := sha256.Sum256(certs[0].Raw)
	return hex.EncodeToString(hash[:]), nil
}