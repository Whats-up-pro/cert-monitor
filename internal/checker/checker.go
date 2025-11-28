// File: internal/checker/checker.go
package checker

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

type CertInfo struct {
	ExpiryDate         time.Time
	Issuer             string
	PublicKeyType      string
	SignatureAlgorithm string
}

// CheckHost checks a single hostname and returns its certificate's expiry date.
func CheckHost(hostname string) (CertInfo, error) {
	// TLS config to skip certificate verification. This is crucial for checking
	// already expired certificates without the connection failing.
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Connect to the server with a timeout to prevent the program from hanging.
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		hostname+":443",
		conf,
	)
	if err != nil {
		return CertInfo{}, fmt.Errorf("could not connect to %s: %w", hostname, err)
	}
	defer conn.Close()

	// Get the peer certificates from the connection state.
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return CertInfo{}, fmt.Errorf("no certificates found for %s", hostname)
	}

	leafCert := certs[0]

	publicKeyTypeString := ""

	switch leafCert.PublicKeyAlgorithm {
	case x509.RSA:
		publicKeyTypeString = "RSA"
	case x509.ECDSA:
		publicKeyTypeString = "ECC (ECDSA)"
	// Thêm các trường hợp khác nếu cần (như DSA)
	default:
		publicKeyTypeString = "Unknown"
	}

	return CertInfo{
		ExpiryDate:         leafCert.NotAfter,
		Issuer:             leafCert.Issuer.Organization[0],
		PublicKeyType:      publicKeyTypeString,
		SignatureAlgorithm: leafCert.SignatureAlgorithm.String(),
	}, nil
	// The first certificate in the chain is the leaf certificate.
	// We return its expiration date.
}
