// File: internal/checker/checker.go
package checker

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// CertInfo cập nhật: Chứa danh sách Fingerprint thay vì 1 cái
type CertInfo struct {
	Domain             string
	ExpiryDate         time.Time
	Issuer             string
	PublicKeyType      string
	SignatureAlgorithm string
	
	// Thay đổi: Danh sách các vân tay hợp lệ (từ nhiều IP của CDN)
	ValidFingerprints []string 
	
	SecurityScore int    
	RiskLevel     string 
	DaysLeft      int
	CheckDuration time.Duration // Thêm thời gian đo đạc cho bài báo
}

// CheckHost nâng cấp: Kiểm tra đa điểm (Multi-IP Check)
func CheckHost(hostname string) (CertInfo, error) {
	start := time.Now()

	// 1. Phân giải DNS để lấy tất cả IP (Xử lý vấn đề CDN)
	cleanHost := strings.TrimSuffix(hostname, ":443")
	if strings.Contains(cleanHost, ":") { // Nếu input có port
		host, _, _ := net.SplitHostPort(hostname)
		cleanHost = host
	}

	ips, err := net.LookupHost(cleanHost)
	if err != nil {
		return CertInfo{}, fmt.Errorf("DNS lookup failed: %v", err)
	}

	// Dùng Map để loại bỏ fingerprint trùng lặp
	fingerprintMap := make(map[string]bool)
	var leafCert *x509.Certificate
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// Giới hạn check tối đa 5 IP để tránh quá lâu (Performance trade-off)
	maxIPs := 5
	if len(ips) > maxIPs {
		ips = ips[:maxIPs]
	}

	// 2. Chạy song song kiểm tra từng IP
	for _, ip := range ips {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			
			// Dial thẳng tới IP nhưng dùng SNI là hostname (cơ chế của CDN)
			conf := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         cleanHost, // QUAN TRỌNG: SNI
			}
			
			dialer := &net.Dialer{Timeout: 3 * time.Second}
			target := net.JoinHostPort(targetIP, "443")
			
			conn, err := tls.DialWithDialer(dialer, "tcp", target, conf)
			if err != nil {
				return
			}
			defer conn.Close()

			certs := conn.ConnectionState().PeerCertificates
			if len(certs) > 0 {
				cert := certs[0]
				hash := sha256.Sum256(cert.Raw)
				fp := hex.EncodeToString(hash[:])

				mutex.Lock()
				fingerprintMap[fp] = true
				if leafCert == nil { // Lấy mẫu 1 cert để điền thông tin chung
					leafCert = cert
				}
				mutex.Unlock()
			}
		}(ip)
	}
	wg.Wait()

	if leafCert == nil {
		return CertInfo{}, fmt.Errorf("failed to retrieve certificate from any IP of %s", hostname)
	}

	// Chuyển map sang slice
	var validFingerprints []string
	for fp := range fingerprintMap {
		validFingerprints = append(validFingerprints, fp)
	}

	// 3. Tính toán các chỉ số (Giữ nguyên logic cũ)
	daysLeft := int(time.Until(leafCert.NotAfter).Hours() / 24)
	score := 100
	risk := "SAFE"

	if daysLeft < 0 {
		score = 0; risk = "CRITICAL"
	} else if daysLeft < 7 {
		score -= 40; risk = "WARNING"
	} else if daysLeft < 30 {
		score -= 20; risk = "WARNING"
	}

	algo := leafCert.SignatureAlgorithm.String()
	if strings.Contains(strings.ToUpper(algo), "SHA1") || strings.Contains(strings.ToUpper(algo), "MD5") {
		score -= 50; risk = "CRITICAL"
	}

	// Lấy Issuer
	issuerName := leafCert.Issuer.CommonName
	if issuerName == "" && len(leafCert.Issuer.Organization) > 0 {
		issuerName = leafCert.Issuer.Organization[0]
	}

	duration := time.Since(start)

	return CertInfo{
		Domain:             hostname,
		ExpiryDate:         leafCert.NotAfter,
		Issuer:             issuerName,
		PublicKeyType:      fmt.Sprintf("%v", leafCert.PublicKeyAlgorithm),
		SignatureAlgorithm: algo,
		ValidFingerprints:  validFingerprints, // Trả về danh sách
		SecurityScore:      score,
		RiskLevel:          risk,
		DaysLeft:           daysLeft,
		CheckDuration:      duration,
	}, nil
}