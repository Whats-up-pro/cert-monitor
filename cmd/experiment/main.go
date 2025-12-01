// File: cmd/experiment/main.go
package main

import (
	"cert-monitor/internal/checker"
	"crypto/sha256"
	"crypto/tls"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const WORKERS = 10 // Số luồng chạy song song

func main() {
	// 1. Đọc file Input (Để file này ở thư mục gốc dự án)
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

	// Header của file báo cáo
	writer.Write([]string{
		"Rank", "Domain", "Status", 
		"Agent_IPs_Found", "Agent_Latency_ms", // Số liệu hiệu năng Server
		"Local_Fingerprint", "Match_Found",    // Số liệu so sánh
		"Is_False_Positive",                   // Cột quan trọng nhất
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
				rank := record[0]
				domain := record[1]
				
				// --- BƯỚC 1: GIẢ LẬP CLIENT (LOCAL) ---
				// Client chỉ kết nối đơn giản, để OS tự chọn IP (DNS mặc định)
				localFP, localErr := getLocalFingerprint(domain)

				// --- BƯỚC 2: GIẢ LẬP SERVER AGENT (REMOTE) ---
				// Agent quét Multi-IP để tìm danh sách hợp lệ
				agentInfo, agentErr := checker.CheckHost(domain)

				// --- BƯỚC 3: PHÂN TÍCH KẾT QUẢ ---
				var row []string
				
				if localErr != nil || agentErr != nil {
					// Nếu lỗi kết nối thì bỏ qua (Error)
					errStr := ""
					if localErr != nil { errStr += "Local: " + localErr.Error() }
					if agentErr != nil { errStr += " Agent: " + agentErr.Error() }
					row = []string{rank, domain, "ERROR", "0", "0", "", "FALSE", "FALSE", errStr}
				} else {
					// So sánh: Local Fingerprint có nằm trong danh sách Agent tìm được không?
					isMatch := false
					for _, remoteFP := range agentInfo.ValidFingerprints {
						if localFP == remoteFP {
							isMatch = true
							break
						}
					}

					// Đánh giá False Positive
					// FP xảy ra khi: Client kết nối được (có FP), Agent kết nối được, nhưng KHÔNG khớp
					// (Giả định môi trường test của bạn là mạng sạch, không có MITM thật)
					isFP := "FALSE"
					status := "SAFE"
					
					if !isMatch {
						isFP = "TRUE"      // Đây chính là False Positive do CDN
						status = "MISMATCH"
					}

					row = []string{
						rank,
						domain,
						status,
						fmt.Sprintf("%d", len(agentInfo.ValidFingerprints)), // Server tìm được bao nhiêu cert?
						fmt.Sprintf("%d", agentInfo.CheckDuration.Milliseconds()),
						localFP[:8] + "...", // Viết tắt cho gọn
						fmt.Sprintf("%v", isMatch),
						isFP, // CỘT QUAN TRỌNG: TRUE là bị Dương tính giả
						"",
					}
				}
				
				results <- row
				fmt.Printf("[%s] %s -> FP: %s (Agent found %d certs)\n", rank, domain, row[7], len(agentInfo.ValidFingerprints))
			}
		}()
	}

	for _, rec := range records { jobs <- rec }
	close(jobs)

	go func() { wg.Wait(); close(results) }()

	for r := range results { writer.Write(r) }
	fmt.Println("Done! Check results_fp_analysis.csv")
}

// Hàm giả lập Client kết nối đơn giản
func getLocalFingerprint(domain string) (string, error) {
	if !strings.Contains(domain, ":") { domain += ":443" }
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", domain, &tls.Config{InsecureSkipVerify: true})
	if err != nil { return "", err }
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 { return "", fmt.Errorf("no certs") }
	hash := sha256.Sum256(certs[0].Raw)
	return hex.EncodeToString(hash[:]), nil
}