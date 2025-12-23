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

	"github.com/miekg/dns" // Thư viện hỗ trợ tạo gói tin DNS tùy chỉnh (ECS)
)

// CertInfo: Chứa thông tin phân tích chứng chỉ và danh sách Fingerprint
type CertInfo struct {
	Domain             string
	ExpiryDate         time.Time
	Issuer             string
	PublicKeyType      string
	SignatureAlgorithm string
	
	// ValidFingerprints: Danh sách các vân tay hợp lệ (từ nhiều IP của CDN)
	ValidFingerprints []string 
	
	SecurityScore int    
	RiskLevel     string 
	DaysLeft      int
	CheckDuration time.Duration 
}

// LookupHostWithECS: Phân giải DNS có sử dụng EDNS Client Subnet
// Giúp Agent lấy được IP của domain tối ưu cho vị trí của User (clientIP)
func LookupHostWithECS(domain string, clientIP string) ([]string, error) {
	// 1. Kiểm tra đầu vào: Nếu không có ClientIP hoặc là Localhost, dùng DNS thường
	if clientIP == "" || clientIP == "127.0.0.1" || clientIP == "::1" {
		return net.LookupHost(domain)
	}

	// Parse IP để đảm bảo đúng định dạng
	parsedIP := net.ParseIP(clientIP)
	if parsedIP == nil {
		return net.LookupHost(domain)
	}

	// 2. Cấu hình DNS Client
	c := new(dns.Client)
	c.Timeout = 2 * time.Second // Timeout ngắn để không làm chậm trải nghiệm
	m := new(dns.Msg)
	
	// Set câu hỏi: Lấy bản ghi A (IPv4)
	// Lưu ý: Domain phải kết thúc bằng dấu chấm (FQDN)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	// 3. Tạo Option ECS (EDNS0_SUBNET)
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	
	e := new(dns.EDNS0_SUBNET)
	e.Code = dns.EDNS0SUBNET
	e.Family = 1 // 1 = IPv4, 2 = IPv6
	e.SourceNetmask = 24 // Chỉ gửi Subnet /24 để bảo vệ quyền riêng tư người dùng
	e.SourceScope = 0
	e.Address = parsedIP.To4() // Gửi IP của User đi kèm query
	
	o.Option = append(o.Option, e)
	m.Extra = append(m.Extra, o)

	// 4. Gửi Query tới Google Public DNS (8.8.8.8 hỗ trợ tốt ECS)
	// Có thể đổi thành Cloudflare (1.1.1.1) hoặc OpenDNS nếu muốn
	r, _, err := c.Exchange(m, "8.8.8.8:53")
	
	// Nếu lỗi ECS (timeout hoặc lỗi mạng), Fallback về lookup thường
	if err != nil {
		// Log warning nếu cần thiết
		return net.LookupHost(domain)
	}

	// 5. Trích xuất IP từ câu trả lời
	var ips []string
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}

	// Nếu ECS không trả về kết quả nào (hiếm), dùng lookup thường
	if len(ips) == 0 {
		return net.LookupHost(domain)
	}

	return ips, nil
}

// CheckHost: Hàm chính thực hiện kiểm tra Multi-IP Aware
// Update: Thêm tham số clientIP để hỗ trợ ECS
func CheckHost(hostname string, clientIP string) (CertInfo, error) {
	start := time.Now()

	// 1. Xử lý hostname (loại bỏ port nếu có)
	cleanHost := strings.TrimSuffix(hostname, ":443")
	if strings.Contains(cleanHost, ":") { 
		host, _, err := net.SplitHostPort(hostname)
		if err == nil {
			cleanHost = host
		}
	}

	// 2. Phân giải DNS thông minh (ECS Aware)
	// Agent sẽ cố gắng "nhìn" thấy các IP giống như User nhìn thấy
	ips, err := LookupHostWithECS(cleanHost, clientIP)
	if err != nil {
		return CertInfo{}, fmt.Errorf("DNS lookup failed: %v", err)
	}

	// Dùng Map để loại bỏ fingerprint trùng lặp
	fingerprintMap := make(map[string]bool)
	var leafCert *x509.Certificate
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// Giới hạn check tối đa 5 IP để tối ưu hiệu năng
	maxIPs := 5
	if len(ips) > maxIPs {
		ips = ips[:maxIPs]
	}

	// 3. Quét song song (Concurrent Scanning)
	for _, ip := range ips {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			
			// Cấu hình TLS:
			// - InsecureSkipVerify: True (Để lấy cert về phân tích, không để Go chặn)
			// - ServerName: cleanHost (Bắt buộc để SNI hoạt động với CDN)
			conf := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         cleanHost, 
			}
			
			// Timeout kết nối ngắn (3s)
			dialer := &net.Dialer{Timeout: 3 * time.Second}
			target := net.JoinHostPort(targetIP, "443")
			
			conn, err := tls.DialWithDialer(dialer, "tcp", target, conf)
			if err != nil {
				return // Bỏ qua IP chết
			}
			defer conn.Close()

			// Lấy chuỗi chứng chỉ
			certs := conn.ConnectionState().PeerCertificates
			if len(certs) > 0 {
				cert := certs[0] // Leaf Certificate
				hash := sha256.Sum256(cert.Raw)
				fp := hex.EncodeToString(hash[:])

				mutex.Lock()
				fingerprintMap[fp] = true
				// Lưu mẫu 1 cert đầy đủ để lấy thông tin metadata (Issuer, Expiry...)
				if leafCert == nil { 
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

	// Chuyển Map thành Slice
	var validFingerprints []string
	for fp := range fingerprintMap {
		validFingerprints = append(validFingerprints, fp)
	}

	// 4. Tính toán điểm số an toàn (Heuristic Scoring)
	daysLeft := int(time.Until(leafCert.NotAfter).Hours() / 24)
	score := 100
	risk := "SAFE"

	// Phạt điểm theo thời hạn
	if daysLeft < 0 {
		score = 0; risk = "CRITICAL" // Hết hạn
	} else if daysLeft < 7 {
		score -= 40; risk = "WARNING"
	} else if daysLeft < 30 {
		score -= 20; risk = "WARNING"
	}

	// Phạt điểm theo thuật toán yếu
	algo := leafCert.SignatureAlgorithm.String()
	algoUpper := strings.ToUpper(algo)
	if strings.Contains(algoUpper, "SHA1") || strings.Contains(algoUpper, "MD5") {
		score -= 50; risk = "CRITICAL"
	}

	// Xử lý tên Issuer hiển thị đẹp hơn
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
		ValidFingerprints:  validFingerprints, // Output quan trọng nhất
		SecurityScore:      score,
		RiskLevel:          risk,
		DaysLeft:           daysLeft,
		CheckDuration:      duration,
	}, nil
}