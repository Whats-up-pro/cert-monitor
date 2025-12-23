// File: cmd/experiment_mitm/main.go
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	WORKERS    = 5                  // Số luồng (chạy ít thôi để Burp không bị đơ)
	PROXY_ADDR = "http://127.0.0.1:8080" // Địa chỉ Burp Suite
	INPUT_FILE = "top-1k.csv"       // File dữ liệu đầu vào (lấy 50 dòng đầu)
)

func main() {
	// 1. Đọc file Input
	f, err := os.Open(INPUT_FILE)
	if err != nil { log.Fatal(err) }
	defer f.Close()
	records, _ := csv.NewReader(f).ReadAll()

	// 2. Tạo file Output
	out, _ := os.Create("mitm_latency_results.csv")
	defer out.Close()
	writer := csv.NewWriter(out)
	// Header cho file CSV
	writer.Write([]string{"Domain", "Local_Latency_ms", "Agent_Latency_ms", "Total_Detection_Time_ms", "Status"})
	defer writer.Flush()

	// 3. Worker Pool
	jobs := make(chan string, len(records))
	results := make(chan []string, len(records))
	var wg sync.WaitGroup

	for w := 0; w < WORKERS; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobs {
				// --- BƯỚC A: Đo thời gian Local (Qua Proxy MITM) ---
				startLocal := time.Now()
				localHash, errLocal := getFingerprintViaProxy(domain)
				durLocal := time.Since(startLocal).Milliseconds()

				// --- BƯỚC B: Đo thời gian Agent (Direct) ---
				startAgent := time.Now()
				agentHash, errAgent := getFingerprintDirect(domain)
				durAgent := time.Since(startAgent).Milliseconds()

				// --- BƯỚC C: Kết luận ---
				status := "UNKNOWN"
				totalTime := durLocal + durAgent

				if errLocal != nil || errAgent != nil {
					status = "ERROR"
				} else if localHash != agentHash {
					status = "MITM_DETECTED" // Đây là kết quả mong đợi
				} else {
					status = "SAFE" // Lẽ ra không được Safe nếu Burp đang bật
				}

				fmt.Printf("[%s] Time: %dms (Local: %d, Agent: %d) -> %s\n", domain, totalTime, durLocal, durAgent, status)
				
				results <- []string{
					domain,
					fmt.Sprintf("%d", durLocal),
					fmt.Sprintf("%d", durAgent),
					fmt.Sprintf("%d", totalTime),
					status,
				}
			}
		}()
	}

	// Chỉ lấy 50 domain đầu để test cho nhanh và vẽ biểu đồ cho đẹp
	limit := 1000
	if len(records) < limit { limit = len(records) }
	
	for i := 0; i < limit; i++ {
		jobs <- records[i][1] // Cột 2 là domain
	}
	close(jobs)

	go func() { wg.Wait(); close(results) }()

	for res := range results { writer.Write(res) }
	fmt.Println("Done! Results saved to mitm_latency_results.csv")
}

// Hàm kết nối qua Burp Proxy
func getFingerprintViaProxy(domain string) (string, error) {
	proxyUrl, _ := url.Parse(PROXY_ADDR)
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyUrl),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Chấp nhận cert giả của Burp
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	
	target := "https://" + strings.TrimSuffix(domain, ":443")
	resp, err := client.Head(target)
	if err != nil { return "", err }
	defer resp.Body.Close()

	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		hash := sha256.Sum256(resp.TLS.PeerCertificates[0].Raw)
		return hex.EncodeToString(hash[:]), nil
	}
	return "", fmt.Errorf("no cert")
}

// Hàm kết nối trực tiếp (Agent)
func getFingerprintDirect(domain string) (string, error) {
    if !strings.Contains(domain, ":") { domain += ":443" }
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", domain, &tls.Config{InsecureSkipVerify: true})
	if err != nil { return "", err }
	defer conn.Close()
	
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		hash := sha256.Sum256(certs[0].Raw)
		return hex.EncodeToString(hash[:]), nil
	}
	return "", fmt.Errorf("no cert")
}