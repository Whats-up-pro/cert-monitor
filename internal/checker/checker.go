// File: internal/checker/checker.go
package checker

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// CheckHost checks a single hostname and returns its certificate's expiry date.
func CheckHost(hostname string) (time.Time, error) {
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
		return time.Time{}, fmt.Errorf("could not connect to %s: %w", hostname, err)
	}
	defer conn.Close()

	// Get the peer certificates from the connection state.
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return time.Time{}, fmt.Errorf("no certificates found for %s", hostname)
	}

	// The first certificate in the chain is the leaf certificate.
	// We return its expiration date.
	return certs[0].NotAfter, nil
}