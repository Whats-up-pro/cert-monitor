// Package fetcher provides certificate fetching from multiple sources
package fetcher

import (
	"cert-monitor/internal/models"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// TLSFetcher handles direct TLS connections to fetch certificates
type TLSFetcher struct {
	// Timeout for TLS connections
	Timeout time.Duration

	// Proxy address (optional, for testing MITM scenarios)
	ProxyAddr string

	// Skip system root verification (for testing)
	InsecureSkipVerify bool
}

// NewTLSFetcher creates a new TLS fetcher with default settings
func NewTLSFetcher() *TLSFetcher {
	return &TLSFetcher{
		Timeout:            10 * time.Second,
		InsecureSkipVerify: true, // We do our own verification
	}
}

// FetchCertificate fetches the certificate chain from a domain
func (f *TLSFetcher) FetchCertificate(ctx context.Context, domain string) (*models.CertificateChain, error) {
	return f.FetchCertificateWithPort(ctx, domain, "443")
}

// FetchCertificateWithPort fetches certificate from a specific port
func (f *TLSFetcher) FetchCertificateWithPort(ctx context.Context, domain, port string) (*models.CertificateChain, error) {
	addr := net.JoinHostPort(domain, port)

	// Configure TLS
	tlsConfig := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: f.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}

	// Create dialer with timeout
	dialer := &net.Dialer{
		Timeout: f.Timeout,
	}

	// Handle proxy if configured
	var conn net.Conn
	var err error

	if f.ProxyAddr != "" {
		// Connect through proxy
		conn, err = dialer.DialContext(ctx, "tcp", f.ProxyAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to proxy: %w", err)
		}
		// CONNECT to target through proxy
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, domain)
		// Read response (simplified - production would parse properly)
		buf := make([]byte, 1024)
		conn.Read(buf)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to %s: %w", domain, err)
		}
	}

	// Upgrade to TLS
	tlsConn := tls.Client(conn, tlsConfig)
	defer tlsConn.Close()

	// Set deadline
	deadline, ok := ctx.Deadline()
	if ok {
		tlsConn.SetDeadline(deadline)
	} else {
		tlsConn.SetDeadline(time.Now().Add(f.Timeout))
	}

	// Perform handshake
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Get peer certificates
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates received from %s", domain)
	}

	// Build certificate chain
	return buildCertificateChain(state.PeerCertificates), nil
}

// FetchCertificateFromMultipleIPs fetches certificates from all resolved IPs
// This handles CDN scenarios where different IPs may serve different certs
func (f *TLSFetcher) FetchCertificateFromMultipleIPs(ctx context.Context, domain string) ([]*models.CertificateChain, error) {
	// Resolve all IPs
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed: %w", err)
	}

	var chains []*models.CertificateChain
	seenFingerprints := make(map[string]bool)

	for _, ip := range ips {
		addr := net.JoinHostPort(ip.IP.String(), "443")

		// Configure TLS with explicit IP
		tlsConfig := &tls.Config{
			ServerName:         domain,
			InsecureSkipVerify: f.InsecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}

		dialer := &net.Dialer{Timeout: f.Timeout}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			continue // Skip unreachable IPs
		}

		tlsConn := tls.Client(conn, tlsConfig)
		tlsConn.SetDeadline(time.Now().Add(f.Timeout))

		if err := tlsConn.Handshake(); err != nil {
			tlsConn.Close()
			continue
		}

		state := tlsConn.ConnectionState()
		tlsConn.Close()

		if len(state.PeerCertificates) == 0 {
			continue
		}

		chain := buildCertificateChain(state.PeerCertificates)

		// Deduplicate based on leaf fingerprint
		if !seenFingerprints[chain.Leaf.Fingerprint] {
			seenFingerprints[chain.Leaf.Fingerprint] = true
			chains = append(chains, chain)
		}
	}

	if len(chains) == 0 {
		return nil, fmt.Errorf("could not fetch certificate from any IP for %s", domain)
	}

	return chains, nil
}

// buildCertificateChain converts x509 certificates to our domain model
func buildCertificateChain(certs []*x509.Certificate) *models.CertificateChain {
	chain := &models.CertificateChain{
		ChainFingerprints: make([]string, 0, len(certs)),
	}

	for i, cert := range certs {
		certInfo := extractCertificateInfo(cert)
		chain.ChainFingerprints = append(chain.ChainFingerprints, certInfo.Fingerprint)

		if i == 0 {
			chain.Leaf = certInfo
		} else if cert.IsCA {
			if cert.Subject.String() == cert.Issuer.String() {
				chain.Root = certInfo
			} else {
				chain.Intermediates = append(chain.Intermediates, certInfo)
			}
		}
	}

	return chain
}

// extractCertificateInfo extracts information from an x509 certificate
func extractCertificateInfo(cert *x509.Certificate) *models.CertificateInfo {
	// Calculate SHA-256 fingerprint
	fingerprint := sha256.Sum256(cert.Raw)

	// Calculate public key fingerprint
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	pubKeyFingerprint := sha256.Sum256(pubKeyBytes)

	// Determine key size
	keySize := 0
	switch pub := cert.PublicKey.(type) {
	case interface{ Size() int }:
		keySize = pub.Size() * 8
	}

	// Check if self-signed
	isSelfSigned := cert.Subject.String() == cert.Issuer.String()

	// Calculate days until expiry
	daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)

	return &models.CertificateInfo{
		Fingerprint:          hex.EncodeToString(fingerprint[:]),
		PublicKeyFingerprint: hex.EncodeToString(pubKeyFingerprint[:]),
		Subject:              cert.Subject.CommonName,
		Issuer:               cert.Issuer.CommonName,
		SerialNumber:         cert.SerialNumber.Text(16),
		SANs:                 cert.DNSNames,
		NotBefore:            cert.NotBefore,
		NotAfter:             cert.NotAfter,
		SignatureAlgorithm:   cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm:   cert.PublicKeyAlgorithm.String(),
		KeySize:              keySize,
		IsSelfSigned:         isSelfSigned,
		ChainDepth:           0, // Set by caller
		DaysUntilExpiry:      daysUntilExpiry,
		RawCertificate:       base64.StdEncoding.EncodeToString(cert.Raw),
		ParsedCert:           cert,
	}
}

// CalculateFingerprint calculates SHA-256 fingerprint of certificate bytes
func CalculateFingerprint(certBytes []byte) string {
	hash := sha256.Sum256(certBytes)
	return hex.EncodeToString(hash[:])
}

// ParseCertificateFromBase64 parses a base64 encoded DER certificate
func ParseCertificateFromBase64(b64 string) (*x509.Certificate, error) {
	derBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// IsWellKnownIssuer checks if the issuer is a well-known CA
func IsWellKnownIssuer(issuer string) bool {
	wellKnownCAs := []string{
		"DigiCert",
		"Let's Encrypt",
		"Sectigo",
		"GoDaddy",
		"GlobalSign",
		"Comodo",
		"Entrust",
		"GeoTrust",
		"Thawte",
		"VeriSign",
		"Amazon",
		"Google Trust Services",
		"Cloudflare",
		"Microsoft",
		"Baltimore CyberTrust",
		"ISRG",
		"Symantec",
	}

	issuerLower := strings.ToLower(issuer)
	for _, ca := range wellKnownCAs {
		if strings.Contains(issuerLower, strings.ToLower(ca)) {
			return true
		}
	}
	return false
}
