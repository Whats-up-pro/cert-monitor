// Package fetcher provides OCSP checking functionality
package fetcher

import (
	"bytes"
	"cert-monitor/internal/models"
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSPFetcher handles OCSP status checks
type OCSPFetcher struct {
	client  *http.Client
	Timeout time.Duration
}

// NewOCSPFetcher creates a new OCSP fetcher
func NewOCSPFetcher() *OCSPFetcher {
	return &OCSPFetcher{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		Timeout: 10 * time.Second,
	}
}

// CheckOCSPStatus checks the OCSP status of a certificate
func (f *OCSPFetcher) CheckOCSPStatus(ctx context.Context, cert *x509.Certificate, issuer *x509.Certificate) (*models.OCSPResult, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}

	// Get OCSP URLs from certificate
	if len(cert.OCSPServer) == 0 {
		return &models.OCSPResult{
			Status: models.OCSPUnknown,
			Error:  "no OCSP server specified in certificate",
		}, nil
	}

	// If no issuer provided, try to use the certificate itself (for self-signed)
	if issuer == nil {
		if cert.IsCA {
			issuer = cert
		} else {
			return &models.OCSPResult{
				Status: models.OCSPUnknown,
				Error:  "issuer certificate required for OCSP check",
			}, nil
		}
	}

	// Create OCSP request
	ocspRequest, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return &models.OCSPResult{
			Status: models.OCSPError,
			Error:  fmt.Sprintf("failed to create OCSP request: %v", err),
		}, nil
	}

	// Try each OCSP server
	var lastErr error
	for _, ocspURL := range cert.OCSPServer {
		result, err := f.queryOCSPServer(ctx, ocspURL, ocspRequest, issuer)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}

	return &models.OCSPResult{
		Status: models.OCSPError,
		Error:  fmt.Sprintf("all OCSP servers failed: %v", lastErr),
	}, nil
}

// queryOCSPServer queries a single OCSP server
func (f *OCSPFetcher) queryOCSPServer(ctx context.Context, ocspURL string, request []byte, issuer *x509.Certificate) (*models.OCSPResult, error) {
	// Try POST request first (preferred)
	result, err := f.queryOCSPPost(ctx, ocspURL, request, issuer)
	if err == nil {
		return result, nil
	}

	// Fall back to GET request
	return f.queryOCSPGet(ctx, ocspURL, request, issuer)
}

// queryOCSPPost sends OCSP request via POST
func (f *OCSPFetcher) queryOCSPPost(ctx context.Context, ocspURL string, request []byte, issuer *x509.Certificate) (*models.OCSPResult, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", ocspURL, bytes.NewReader(request))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return f.parseOCSPResponse(body, issuer)
}

// queryOCSPGet sends OCSP request via GET (base64 encoded)
func (f *OCSPFetcher) queryOCSPGet(ctx context.Context, ocspURL string, request []byte, issuer *x509.Certificate) (*models.OCSPResult, error) {
	// Base64 encode the request
	encoded := url.PathEscape(base64.StdEncoding.EncodeToString(request))

	// Construct URL
	fullURL := ocspURL
	if fullURL[len(fullURL)-1] != '/' {
		fullURL += "/"
	}
	fullURL += encoded

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/ocsp-response")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return f.parseOCSPResponse(body, issuer)
}

// parseOCSPResponse parses an OCSP response
func (f *OCSPFetcher) parseOCSPResponse(responseBytes []byte, issuer *x509.Certificate) (*models.OCSPResult, error) {
	response, err := ocsp.ParseResponse(responseBytes, issuer)
	if err != nil {
		// Try parsing without issuer verification
		response, err = ocsp.ParseResponseForCert(responseBytes, nil, issuer)
		if err != nil {
			return &models.OCSPResult{
				Status: models.OCSPError,
				Error:  fmt.Sprintf("failed to parse OCSP response: %v", err),
			}, nil
		}
	}

	result := &models.OCSPResult{
		ProducedAt: response.ProducedAt,
		ThisUpdate: response.ThisUpdate,
		NextUpdate: response.NextUpdate,
	}

	switch response.Status {
	case ocsp.Good:
		result.Status = models.OCSPGood
	case ocsp.Revoked:
		result.Status = models.OCSPRevoked
		result.RevokedAt = &response.RevokedAt
		result.RevocationReason = ocspRevocationReasonString(response.RevocationReason)
	case ocsp.Unknown:
		result.Status = models.OCSPUnknown
	default:
		result.Status = models.OCSPUnknown
	}

	return result, nil
}

// ocspRevocationReasonString converts revocation reason to string
func ocspRevocationReasonString(reason int) string {
	reasons := map[int]string{
		0:  "Unspecified",
		1:  "KeyCompromise",
		2:  "CACompromise",
		3:  "AffiliationChanged",
		4:  "Superseded",
		5:  "CessationOfOperation",
		6:  "CertificateHold",
		8:  "RemoveFromCRL",
		9:  "PrivilegeWithdrawn",
		10: "AACompromise",
	}

	if s, ok := reasons[reason]; ok {
		return s
	}
	return fmt.Sprintf("Unknown(%d)", reason)
}

// CheckOCSPStapling checks for OCSP stapling in TLS connection
func (f *OCSPFetcher) CheckOCSPStapling(ocspStaple []byte, cert *x509.Certificate, issuer *x509.Certificate) (*models.OCSPResult, error) {
	if len(ocspStaple) == 0 {
		return &models.OCSPResult{
			Status: models.OCSPUnknown,
			Error:  "no OCSP staple present",
		}, nil
	}

	return f.parseOCSPResponse(ocspStaple, issuer)
}

// OCSPStatusScore calculates a score based on OCSP status
func OCSPStatusScore(result *models.OCSPResult) float64 {
	switch result.Status {
	case models.OCSPGood:
		return 1.0
	case models.OCSPRevoked:
		return 0.0 // Certificate is revoked - critical failure
	case models.OCSPUnknown:
		return 0.5 // Unknown - neutral
	case models.OCSPError:
		return 0.5 // Could not check - neutral
	default:
		return 0.5
	}
}

// IsOCSPResponseFresh checks if OCSP response is still valid
func IsOCSPResponseFresh(result *models.OCSPResult) bool {
	if result.Status == models.OCSPError {
		return false
	}

	now := time.Now()

	// Check if within validity period
	if now.Before(result.ThisUpdate) {
		return false // Response is in the future
	}

	if !result.NextUpdate.IsZero() && now.After(result.NextUpdate) {
		return false // Response has expired
	}

	return true
}
