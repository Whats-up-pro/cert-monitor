// Package core provides the multi-dimensional validator for Cert-Monitor v2.0
package core

import (
	"cert-monitor/internal/analyzer"
	"cert-monitor/internal/fetcher"
	"cert-monitor/internal/models"
	"context"
	"fmt"
	"sync"
	"time"
)

// MultiDimensionalValidator orchestrates validation across multiple dimensions
type MultiDimensionalValidator struct {
	// Component dependencies
	tlsFetcher   *fetcher.TLSFetcher
	ctFetcher    *fetcher.CTLogFetcher
	ocspFetcher  *fetcher.OCSPFetcher
	heuristic    *analyzer.HeuristicAnalyzer
	mlDetector   *analyzer.MLAnomalyDetector
	cache        *TOFUCache

	// Configuration
	Config ValidatorConfig
}

// ValidatorConfig holds configuration for the validator
type ValidatorConfig struct {
	// Enable/disable specific dimensions
	EnableFingerprint bool
	EnableCT          bool
	EnableOCSP        bool
	EnableDNSCAA      bool
	EnableHistorical  bool
	EnableML          bool

	// Timeouts
	TotalTimeout    time.Duration
	PerCheckTimeout time.Duration

	// Thresholds
	MITMThreshold       float64 // Score below this = MITM_DETECTED
	SuspiciousThreshold float64 // Score below this = SUSPICIOUS

	// CDN handling
	AllowCDNVariance bool
}

// DefaultValidatorConfig returns sensible defaults
func DefaultValidatorConfig() ValidatorConfig {
	return ValidatorConfig{
		EnableFingerprint: true,
		EnableCT:          true,
		EnableOCSP:        true,
		EnableDNSCAA:      false, // Not implemented yet
		EnableHistorical:  true,
		EnableML:          true,
		TotalTimeout:      30 * time.Second,
		PerCheckTimeout:   10 * time.Second,
		MITMThreshold:     0.3,
		SuspiciousThreshold: 0.6,
		AllowCDNVariance:  true,
	}
}

// TOFUCache provides Trust On First Use caching
type TOFUCache struct {
	entries map[string]*CacheEntry
	mu      sync.RWMutex
	TTL     time.Duration
}

// NewTOFUCache creates a new TOFU cache
func NewTOFUCache(ttl time.Duration) *TOFUCache {
	return &TOFUCache{
		entries: make(map[string]*CacheEntry),
		TTL:     ttl,
	}
}

// Get retrieves a cache entry
func (c *TOFUCache) Get(domain string) (*CacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[domain]
	if !exists {
		return nil, false
	}

	// Check expiry
	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

	return entry, true
}

// Set stores a cache entry
func (c *TOFUCache) Set(domain string, entry *CacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry.ExpiresAt = time.Now().Add(c.TTL)
	c.entries[domain] = entry
}

// NewMultiDimensionalValidator creates a new validator with all components
func NewMultiDimensionalValidator(config ValidatorConfig) *MultiDimensionalValidator {
	return &MultiDimensionalValidator{
		tlsFetcher:  fetcher.NewTLSFetcher(),
		ctFetcher:   fetcher.NewCTLogFetcher(),
		ocspFetcher: fetcher.NewOCSPFetcher(),
		heuristic:   analyzer.NewHeuristicAnalyzer(),
		mlDetector:  analyzer.NewMLAnomalyDetector(),
		cache:       NewTOFUCache(24 * time.Hour),
		Config:      config,
	}
}

// Validate performs multi-dimensional validation of a domain
func (v *MultiDimensionalValidator) Validate(ctx context.Context, req *VerificationRequest) *VerificationResponse {
	startTime := time.Now()

	response := &VerificationResponse{
		RequestID:  req.RequestID,
		Timestamp:  time.Now().Unix(),
		Dimensions: make([]DimensionResult, 0),
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, v.Config.TotalTimeout)
	defer cancel()

	// Step 1: Fetch certificate from server (Agent's perspective)
	agentChains, err := v.tlsFetcher.FetchCertificateFromMultipleIPs(ctx, req.Domain)
	if err != nil {
		response.Verdict = VerdictError
		response.Error = fmt.Sprintf("Failed to fetch certificate: %v", err)
		response.Message = "Could not connect to target server"
		response.LatencyMs = time.Since(startTime).Milliseconds()
		return response
	}

	if len(agentChains) == 0 {
		response.Verdict = VerdictError
		response.Error = "No certificates retrieved from server"
		response.LatencyMs = time.Since(startTime).Milliseconds()
		return response
	}

	// Get the leaf certificate from agent's perspective
	agentLeaf := agentChains[0].Leaf

	// Run all dimension checks in parallel
	var wg sync.WaitGroup
	dimResults := make(chan DimensionResult, 10)

	// Dimension 1: Fingerprint comparison (Split-View core)
	if v.Config.EnableFingerprint {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dimResults <- v.checkFingerprint(req.ClientCertFingerprint, agentChains)
		}()
	}

	// Dimension 2: CT Log presence
	if v.Config.EnableCT {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dimResults <- v.checkCTPresence(ctx, agentLeaf.Fingerprint)
		}()
	}

	// Dimension 3: OCSP Status
	if v.Config.EnableOCSP && agentLeaf.ParsedCert != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dimResults <- v.checkOCSPStatus(ctx, agentChains[0])
		}()
	}

	// Dimension 4: Historical (TOFU)
	if v.Config.EnableHistorical {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dimResults <- v.checkHistorical(req.Domain, agentLeaf.Fingerprint)
		}()
	}

	// Dimension 5: Heuristic analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		dimResults <- v.checkHeuristic(agentLeaf)
	}()

	// Dimension 6: ML Anomaly
	if v.Config.EnableML {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dimResults <- v.checkMLAnomaly(agentLeaf)
		}()
	}

	// Wait for all checks to complete
	go func() {
		wg.Wait()
		close(dimResults)
	}()

	// Collect results
	for result := range dimResults {
		response.Dimensions = append(response.Dimensions, result)
	}

	// Calculate final scores
	response.SecurityScore = v.calculateSecurityScore(response.Dimensions)
	response.AnomalyScore = v.getMLAnomalyScore(response.Dimensions)
	response.Confidence = v.calculateConfidence(response.Dimensions)

	// Determine verdict
	response.Verdict = v.determineVerdict(response)

	// Generate message
	response.Message = v.generateMessage(response)

	// Update cache on success
	if response.Verdict == VerdictSafe {
		v.cache.Set(req.Domain, &CacheEntry{
			Domain:            req.Domain,
			Fingerprint:       agentLeaf.Fingerprint,
			CertInfo:          agentLeaf,
			CreatedAt:         time.Now(),
			VerificationCount: 1,
			LastVerified:      time.Now(),
			SecurityScore:     response.SecurityScore,
		})
	}

	response.LatencyMs = time.Since(startTime).Milliseconds()
	return response
}

// checkFingerprint compares client fingerprint against agent's observations
func (v *MultiDimensionalValidator) checkFingerprint(clientFP string, agentChains []*models.CertificateChain) DimensionResult {
	start := time.Now()

	result := DimensionResult{
		Dimension: DimFingerprint,
		Weight:    DimensionWeights[DimFingerprint],
	}

	if clientFP == "" {
		result.Status = StatusSkipped
		result.Score = 0.5
		result.Details = "No client fingerprint provided"
		result.LatencyMs = time.Since(start).Milliseconds()
		return result
	}

	// Check if client fingerprint matches any of the agent's observed fingerprints
	for _, chain := range agentChains {
		if chain.Leaf.Fingerprint == clientFP {
			result.Status = StatusPass
			result.Score = 1.0
			result.Details = "Client fingerprint matches server certificate"
			result.LatencyMs = time.Since(start).Milliseconds()
			return result
		}

		// Also check chain fingerprints for CDN scenarios
		for _, fp := range chain.ChainFingerprints {
			if fp == clientFP {
				result.Status = StatusPass
				result.Score = 1.0
				result.Details = "Client fingerprint matches certificate chain"
				result.LatencyMs = time.Since(start).Milliseconds()
				return result
			}
		}
	}

	// MITM DETECTED - fingerprints don't match
	result.Status = StatusFail
	result.Score = 0.0
	result.Details = fmt.Sprintf("MITM DETECTED: Client sees fingerprint %s, but server has different certificate", clientFP[:16]+"...")
	result.LatencyMs = time.Since(start).Milliseconds()
	return result
}

// checkCTPresence verifies certificate is in CT logs
func (v *MultiDimensionalValidator) checkCTPresence(ctx context.Context, fingerprint string) DimensionResult {
	start := time.Now()

	result := DimensionResult{
		Dimension: DimCTPresence,
		Weight:    DimensionWeights[DimCTPresence],
	}

	ctResult, err := v.ctFetcher.QueryCTLogs(ctx, fingerprint)
	if err != nil {
		result.Status = StatusUnknown
		result.Score = 0.5
		result.Details = fmt.Sprintf("CT query failed: %v", err)
		result.LatencyMs = time.Since(start).Milliseconds()
		return result
	}

	if ctResult.Found {
		result.Status = StatusPass
		result.Score = fetcher.CTPresenceScore(ctResult)
		result.Details = fmt.Sprintf("Found in %d CT logs: %v", ctResult.LogCount, ctResult.LogNames)
	} else {
		result.Status = StatusWarning
		result.Score = 0.3
		result.Details = "Certificate not found in Certificate Transparency logs"
	}

	result.LatencyMs = time.Since(start).Milliseconds()
	return result
}

// checkOCSPStatus verifies certificate revocation status
func (v *MultiDimensionalValidator) checkOCSPStatus(ctx context.Context, chain *models.CertificateChain) DimensionResult {
	start := time.Now()

	result := DimensionResult{
		Dimension: DimOCSPStatus,
		Weight:    DimensionWeights[DimOCSPStatus],
	}

	if chain.Leaf.ParsedCert == nil {
		result.Status = StatusSkipped
		result.Score = 0.5
		result.Details = "No parsed certificate available for OCSP check"
		result.LatencyMs = time.Since(start).Milliseconds()
		return result
	}

	// Get issuer certificate
	var issuerCert = chain.Leaf.ParsedCert
	if len(chain.Intermediates) > 0 && chain.Intermediates[0].ParsedCert != nil {
		issuerCert = chain.Intermediates[0].ParsedCert
	}

	ocspResult, err := v.ocspFetcher.CheckOCSPStatus(ctx, chain.Leaf.ParsedCert, issuerCert)
	if err != nil {
		result.Status = StatusUnknown
		result.Score = 0.5
		result.Details = fmt.Sprintf("OCSP check failed: %v", err)
		result.LatencyMs = time.Since(start).Milliseconds()
		return result
	}

	result.Score = fetcher.OCSPStatusScore(ocspResult)

	switch ocspResult.Status {
	case models.OCSPGood:
		result.Status = StatusPass
		result.Details = "OCSP status: Good (not revoked)"
	case models.OCSPRevoked:
		result.Status = StatusFail
		result.Score = 0.0
		result.Details = fmt.Sprintf("CRITICAL: Certificate revoked - %s", ocspResult.RevocationReason)
	default:
		result.Status = StatusUnknown
		result.Details = "OCSP status unknown"
	}

	result.LatencyMs = time.Since(start).Milliseconds()
	return result
}

// checkHistorical compares against TOFU cache
func (v *MultiDimensionalValidator) checkHistorical(domain, fingerprint string) DimensionResult {
	start := time.Now()

	result := DimensionResult{
		Dimension: DimHistorical,
		Weight:    DimensionWeights[DimHistorical],
	}

	entry, exists := v.cache.Get(domain)
	if !exists {
		result.Status = StatusUnknown
		result.Score = 0.5
		result.Details = "First visit - no historical data (Cold Start)"
		result.LatencyMs = time.Since(start).Milliseconds()
		return result
	}

	if entry.Fingerprint == fingerprint {
		result.Status = StatusPass
		result.Score = 1.0
		result.Details = fmt.Sprintf("Fingerprint matches cached entry (verified %d times)", entry.VerificationCount)
	} else {
		result.Status = StatusWarning
		result.Score = 0.3
		result.Details = "Certificate changed since last verification - could be rotation or MITM"
	}

	result.LatencyMs = time.Since(start).Milliseconds()
	return result
}


// checkHeuristic runs heuristic analysis
func (v *MultiDimensionalValidator) checkHeuristic(cert *models.CertificateInfo) DimensionResult {
	start := time.Now()

	result := DimensionResult{
		Dimension: DimChainValidity,
		Weight:    DimensionWeights[DimChainValidity],
	}

	hResult := v.heuristic.Analyze(cert)
	result.Score = hResult.OverallScore / 100.0 // Normalize to 0-1

	switch hResult.RiskLevel {
	case "LOW":
		result.Status = StatusPass
		result.Details = fmt.Sprintf("Heuristic score: %.1f/100 (Low risk)", hResult.OverallScore)
	case "MEDIUM":
		result.Status = StatusWarning
		result.Details = fmt.Sprintf("Heuristic score: %.1f/100 (Medium risk)", hResult.OverallScore)
	case "HIGH":
		result.Status = StatusWarning
		result.Details = fmt.Sprintf("Heuristic score: %.1f/100 (High risk)", hResult.OverallScore)
	case "CRITICAL":
		result.Status = StatusFail
		result.Details = fmt.Sprintf("Heuristic score: %.1f/100 (Critical risk)", hResult.OverallScore)
	}

	if len(hResult.Warnings) > 0 {
		result.Details += " | Warnings: " + hResult.Warnings[0]
	}

	result.LatencyMs = time.Since(start).Milliseconds()
	return result
}

// checkMLAnomaly runs ML-based anomaly detection
func (v *MultiDimensionalValidator) checkMLAnomaly(cert *models.CertificateInfo) DimensionResult {
	start := time.Now()

	result := DimensionResult{
		Dimension: DimMLAnomaly,
		Weight:    DimensionWeights[DimMLAnomaly],
	}

	prediction := v.mlDetector.Predict(cert)
	result.Score = 1.0 - prediction.AnomalyScore // Invert: high anomaly = low score

	if prediction.AnomalyScore < 0.3 {
		result.Status = StatusPass
		result.Details = fmt.Sprintf("ML anomaly score: %.2f (Normal)", prediction.AnomalyScore)
	} else if prediction.AnomalyScore < 0.6 {
		result.Status = StatusWarning
		result.Details = fmt.Sprintf("ML anomaly score: %.2f (Elevated)", prediction.AnomalyScore)
	} else {
		result.Status = StatusFail
		result.Details = fmt.Sprintf("ML anomaly score: %.2f (High anomaly)", prediction.AnomalyScore)
	}

	if len(prediction.TopFeatures) > 0 {
		result.Details += fmt.Sprintf(" | Top factor: %s", prediction.TopFeatures[0].FeatureName)
	}

	result.LatencyMs = time.Since(start).Milliseconds()
	return result
}

// calculateSecurityScore computes weighted average of all dimensions
func (v *MultiDimensionalValidator) calculateSecurityScore(dimensions []DimensionResult) float64 {
	var totalWeight float64
	var weightedSum float64

	for _, dim := range dimensions {
		if dim.Status != StatusSkipped {
			totalWeight += dim.Weight
			weightedSum += dim.Score * dim.Weight
		}
	}

	if totalWeight == 0 {
		return 0.5
	}

	return (weightedSum / totalWeight) * 100.0
}

// getMLAnomalyScore extracts ML anomaly score from dimensions
func (v *MultiDimensionalValidator) getMLAnomalyScore(dimensions []DimensionResult) float64 {
	for _, dim := range dimensions {
		if dim.Dimension == DimMLAnomaly {
			return 1.0 - dim.Score // Convert back to anomaly score
		}
	}
	return 0.0
}

// calculateConfidence computes overall confidence
func (v *MultiDimensionalValidator) calculateConfidence(dimensions []DimensionResult) float64 {
	passCount := 0
	totalCount := 0

	for _, dim := range dimensions {
		if dim.Status != StatusSkipped && dim.Status != StatusUnknown {
			totalCount++
			if dim.Status == StatusPass {
				passCount++
			}
		}
	}

	if totalCount == 0 {
		return 0.5
	}

	return float64(passCount) / float64(totalCount)
}

// determineVerdict determines the final verdict
func (v *MultiDimensionalValidator) determineVerdict(response *VerificationResponse) Verdict {
	// Check for critical failures
	for _, dim := range response.Dimensions {
		if dim.Dimension == DimFingerprint && dim.Status == StatusFail {
			return VerdictMITMDetected
		}
		if dim.Dimension == DimOCSPStatus && dim.Status == StatusFail {
			return VerdictMITMDetected // Revoked cert
		}
	}

	// Check security score
	if response.SecurityScore < v.Config.MITMThreshold*100 {
		return VerdictMITMDetected
	}

	if response.SecurityScore < v.Config.SuspiciousThreshold*100 {
		return VerdictSuspicious
	}

	return VerdictSafe
}

// generateMessage creates human-readable message
func (v *MultiDimensionalValidator) generateMessage(response *VerificationResponse) string {
	switch response.Verdict {
	case VerdictSafe:
		return fmt.Sprintf("Connection is secure. Security score: %.1f/100", response.SecurityScore)
	case VerdictMITMDetected:
		return "⚠️ MITM ATTACK DETECTED - Connection is being intercepted!"
	case VerdictSuspicious:
		return fmt.Sprintf("Certificate has suspicious characteristics. Security score: %.1f/100", response.SecurityScore)
	case VerdictError:
		return "Could not verify certificate: " + response.Error
	default:
		return "Verification completed"
	}
}
