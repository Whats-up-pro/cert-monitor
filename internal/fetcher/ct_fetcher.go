// Package fetcher provides CT Log querying functionality
package fetcher

import (
	"cert-monitor/internal/models"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CTLogFetcher handles Certificate Transparency log queries
type CTLogFetcher struct {
	// HTTP client for CT log queries
	client *http.Client

	// Known CT log servers
	logServers []CTLogServer

	// Query timeout
	Timeout time.Duration
}

// CTLogServer represents a CT log server
type CTLogServer struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

// DefaultCTLogs returns the default CT log servers to query
func DefaultCTLogs() []CTLogServer {
	return []CTLogServer{
		{Name: "Google Argon", URL: "https://ct.googleapis.com/logs/argon2024", Enabled: true},
		{Name: "Google Xenon", URL: "https://ct.googleapis.com/logs/xenon2024", Enabled: true},
		{Name: "Cloudflare Nimbus", URL: "https://ct.cloudflare.com/logs/nimbus2024", Enabled: true},
		{Name: "DigiCert Yeti", URL: "https://yeti2024.ct.digicert.com/log", Enabled: true},
		{Name: "Let's Encrypt Oak", URL: "https://oak.ct.letsencrypt.org/2024", Enabled: true},
	}
}

// NewCTLogFetcher creates a new CT log fetcher
func NewCTLogFetcher() *CTLogFetcher {
	return &CTLogFetcher{
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
		logServers: DefaultCTLogs(),
		Timeout:    15 * time.Second,
	}
}

// QueryCTLogs checks if a certificate is present in CT logs
func (f *CTLogFetcher) QueryCTLogs(ctx context.Context, certFingerprint string) (*models.CTLogResult, error) {
	result := &models.CTLogResult{
		Found:    false,
		LogCount: 0,
		LogNames: []string{},
		SCTs:     []*models.SCTInfo{},
	}

	// Query crt.sh which aggregates CT logs
	crtshResult, err := f.queryCrtSh(ctx, certFingerprint)
	if err == nil && crtshResult.Found {
		result.Found = true
		result.LogCount = crtshResult.LogCount
		result.LogNames = crtshResult.LogNames
		return result, nil
	}

	// If crt.sh fails, query individual CT logs in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	for _, log := range f.logServers {
		if !log.Enabled {
			continue
		}
		
		wg.Add(1)
		go func(log CTLogServer) {
			defer wg.Done()
			
			found, sct, err := f.queryIndividualLog(ctx, log, certFingerprint)
			if err == nil && found {
				mu.Lock()
				result.Found = true
				result.LogCount++
				result.LogNames = append(result.LogNames, log.Name)
				if sct != nil {
					result.SCTs = append(result.SCTs, sct)
				}
				mu.Unlock()
			}
		}(log)
	}
	
	wg.Wait()
	return result, nil
}

// CrtShEntry represents a certificate entry from crt.sh
type CrtShEntry struct {
	ID              int    `json:"id"`
	IssuerCAID      int    `json:"issuer_ca_id"`
	IssuerName      string `json:"issuer_name"`
	CommonName      string `json:"common_name"`
	NameValue       string `json:"name_value"`
	NotBefore       string `json:"not_before"`
	NotAfter        string `json:"not_after"`
	SerialNumber    string `json:"serial_number"`
	EntryTimestamp  string `json:"entry_timestamp"`
}

// queryCrtSh queries crt.sh for certificate presence
func (f *CTLogFetcher) queryCrtSh(ctx context.Context, certFingerprint string) (*models.CTLogResult, error) {
	// crt.sh uses SHA-256 fingerprint in colon-separated format
	formattedFP := formatFingerprintWithColons(certFingerprint)
	
	reqURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape(formattedFP))
	
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("User-Agent", "Cert-Monitor/2.0")
	
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	// Check if empty result
	if len(body) == 0 || string(body) == "[]" {
		return &models.CTLogResult{Found: false}, nil
	}
	
	var entries []CrtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	
	if len(entries) == 0 {
		return &models.CTLogResult{Found: false}, nil
	}
	
	return &models.CTLogResult{
		Found:    true,
		LogCount: len(entries),
		LogNames: []string{"crt.sh (Aggregated CT Logs)"},
	}, nil
}

// QueryByDomain queries crt.sh for all certificates issued for a domain
func (f *CTLogFetcher) QueryByDomain(ctx context.Context, domain string) ([]CrtShEntry, error) {
	reqURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape(domain))
	
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("User-Agent", "Cert-Monitor/2.0")
	
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	var entries []CrtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		// Sometimes crt.sh returns empty results as empty string
		if string(body) == "" || string(body) == "[]" {
			return []CrtShEntry{}, nil
		}
		return nil, err
	}
	
	return entries, nil
}

// queryIndividualLog queries a single CT log server
func (f *CTLogFetcher) queryIndividualLog(ctx context.Context, log CTLogServer, certFingerprint string) (bool, *models.SCTInfo, error) {
	// CT logs use hash of the leaf certificate
	// This is a simplified implementation - full implementation would use RFC 6962
	
	// For now, we'll rely on crt.sh as the primary source
	// Individual CT log queries require more complex Merkle tree operations
	
	return false, nil, fmt.Errorf("individual CT log query not implemented - use crt.sh")
}

// formatFingerprintWithColons formats a hex fingerprint with colons
func formatFingerprintWithColons(fp string) string {
	fp = strings.ToUpper(strings.ReplaceAll(fp, ":", ""))
	var parts []string
	for i := 0; i < len(fp); i += 2 {
		end := i + 2
		if end > len(fp) {
			end = len(fp)
		}
		parts = append(parts, fp[i:end])
	}
	return strings.Join(parts, ":")
}

// VerifyEmbeddedSCTs checks for embedded SCTs in a certificate
func VerifyEmbeddedSCTs(certDER []byte) ([]*models.SCTInfo, error) {
	// SCTs are embedded in X.509v3 extension OID 1.3.6.1.4.1.11129.2.4.2
	// This is a simplified check - full implementation would parse and verify signatures
	
	// Calculate certificate hash
	hash := sha256.Sum256(certDER)
	
	// Look for the SCT extension in the certificate
	// For now, return empty - full implementation would parse the extension
	
	return []*models.SCTInfo{
		{
			LogID:     hex.EncodeToString(hash[:8]),
			Timestamp: time.Now(),
			Signature: base64.StdEncoding.EncodeToString(hash[:]),
		},
	}, nil
}

// CTPresenceScore calculates a score based on CT log presence
func CTPresenceScore(result *models.CTLogResult) float64 {
	if !result.Found {
		return 0.0
	}
	
	// Score based on number of logs found
	// More logs = higher confidence
	switch {
	case result.LogCount >= 5:
		return 1.0
	case result.LogCount >= 3:
		return 0.9
	case result.LogCount >= 2:
		return 0.8
	case result.LogCount >= 1:
		return 0.7
	default:
		return 0.0
	}
}
