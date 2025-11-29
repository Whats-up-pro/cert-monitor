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
	"time"
)

// CertInfo chứa thông tin chi tiết để trả về
type CertInfo struct {
	Domain             string
	ExpiryDate         time.Time
	Issuer             string
	PublicKeyType      string
	SignatureAlgorithm string
	Fingerprint   string 
	SecurityScore int    // Thang điểm 100
	RiskLevel     string // SAFE, WARNING, CRITICAL
	DaysLeft      int
}

// CheckHost kết nối và phân tích chứng chỉ
func CheckHost(hostname string) (CertInfo, error) {
	// Cấu hình bỏ qua lỗi verify để lấy cert về phân tích (kể cả khi đã hết hạn)
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Thêm port 443 nếu thiếu
	target := hostname
	if !strings.Contains(target, ":") {
		target = target + ":443"
	}

	// Kết nối với timeout
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		target,
		conf,
	)
	if err != nil {
		return CertInfo{}, fmt.Errorf("could not connect to %s: %w", hostname, err)
	}
	defer conn.Close()

	// Lấy danh sách chứng chỉ
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return CertInfo{}, fmt.Errorf("no certificates found for %s", hostname)
	}

	leafCert := certs[0]

	// 1. Xác định loại Public Key
	publicKeyTypeString := "Unknown"
	switch leafCert.PublicKeyAlgorithm {
	case x509.RSA:
		publicKeyTypeString = "RSA"
	case x509.ECDSA:
		publicKeyTypeString = "ECC (ECDSA)"
	}

	// 2. Tính SHA-256 Fingerprint
	// Đây là "Vân tay" duy nhất của chứng chỉ, dùng để phát hiện MITM
	hash := sha256.Sum256(leafCert.Raw)
	fingerprint := hex.EncodeToString(hash[:])

	// 3. Tính ngày còn lại
	daysLeft := int(time.Until(leafCert.NotAfter).Hours() / 24)

	// 4. Thuật toán chấm điểm (Heuristic Scoring)
	score := 100
	risk := "SAFE"

	// Trừ điểm theo hạn dùng
	if daysLeft < 0 {
		score = 0
		risk = "CRITICAL" // Hết hạn
	} else if daysLeft < 7 {
		score -= 40
		risk = "WARNING"
	} else if daysLeft < 30 {
		score -= 20
		risk = "WARNING"
	}

	// Trừ điểm theo thuật toán yếu (Ví dụ: SHA1)
	algo := leafCert.SignatureAlgorithm.String()
	if strings.Contains(strings.ToUpper(algo), "SHA1") || strings.Contains(strings.ToUpper(algo), "MD5") {
		score -= 50
		risk = "CRITICAL" // Thuật toán yếu dễ bị bẻ khóa
	}

	// Lấy Issuer (ưu tiên CommonName)
	issuerName := leafCert.Issuer.CommonName
	if issuerName == "" && len(leafCert.Issuer.Organization) > 0 {
		issuerName = leafCert.Issuer.Organization[0]
	}

	return CertInfo{
		Domain:             hostname,
		ExpiryDate:         leafCert.NotAfter,
		Issuer:             issuerName,
		PublicKeyType:      publicKeyTypeString,
		SignatureAlgorithm: algo,
		Fingerprint:        fingerprint,   
		SecurityScore:      score,         
		RiskLevel:          risk,          
		DaysLeft:           daysLeft,
	}, nil
}