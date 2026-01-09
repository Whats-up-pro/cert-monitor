// Package analyzer provides certificate analysis functionality
package analyzer

import (
	"cert-monitor/internal/models"
	"math"
	"strings"
	"time"
)

// HeuristicAnalyzer performs heuristic-based certificate analysis
type HeuristicAnalyzer struct {
	// Configurable weights for each factor
	Weights HeuristicWeights
}

// HeuristicWeights defines the weight for each heuristic factor
type HeuristicWeights struct {
	KeyStrength       float64 `json:"key_strength"`
	ValidityPeriod    float64 `json:"validity_period"`
	IssuerReputation  float64 `json:"issuer_reputation"`
	ChainDepth        float64 `json:"chain_depth"`
	SignatureAlgo     float64 `json:"signature_algo"`
	SANConfiguration  float64 `json:"san_configuration"`
	CertificateAge    float64 `json:"certificate_age"`
	ExpiryProximity   float64 `json:"expiry_proximity"`
}

// DefaultHeuristicWeights returns sensible default weights
func DefaultHeuristicWeights() HeuristicWeights {
	return HeuristicWeights{
		KeyStrength:      0.20,
		ValidityPeriod:   0.15,
		IssuerReputation: 0.20,
		ChainDepth:       0.10,
		SignatureAlgo:    0.15,
		SANConfiguration: 0.05,
		CertificateAge:   0.05,
		ExpiryProximity:  0.10,
	}
}

// NewHeuristicAnalyzer creates a new analyzer with default weights
func NewHeuristicAnalyzer() *HeuristicAnalyzer {
	return &HeuristicAnalyzer{
		Weights: DefaultHeuristicWeights(),
	}
}

// HeuristicResult contains the detailed heuristic analysis result
type HeuristicResult struct {
	// Overall score (0-100)
	OverallScore float64 `json:"overall_score"`

	// Individual factor scores
	Factors []HeuristicFactor `json:"factors"`

	// Risk level: LOW, MEDIUM, HIGH, CRITICAL
	RiskLevel string `json:"risk_level"`

	// Warnings and recommendations
	Warnings []string `json:"warnings"`
}

// HeuristicFactor represents a single scoring factor
type HeuristicFactor struct {
	Name        string  `json:"name"`
	Score       float64 `json:"score"`       // 0-1
	Weight      float64 `json:"weight"`      // 0-1
	WeightedScore float64 `json:"weighted_score"`
	Details     string  `json:"details"`
	Status      string  `json:"status"` // GOOD, WARNING, BAD
}

// Analyze performs a comprehensive heuristic analysis of a certificate
func (h *HeuristicAnalyzer) Analyze(certInfo *models.CertificateInfo) *HeuristicResult {
	result := &HeuristicResult{
		Factors:  make([]HeuristicFactor, 0),
		Warnings: make([]string, 0),
	}

	// Calculate each factor
	factors := []HeuristicFactor{
		h.analyzeKeyStrength(certInfo),
		h.analyzeValidityPeriod(certInfo),
		h.analyzeIssuerReputation(certInfo),
		h.analyzeChainDepth(certInfo),
		h.analyzeSignatureAlgorithm(certInfo),
		h.analyzeSANConfiguration(certInfo),
		h.analyzeCertificateAge(certInfo),
		h.analyzeExpiryProximity(certInfo),
	}

	// Calculate weighted score
	var totalWeight float64
	var weightedSum float64

	for _, factor := range factors {
		result.Factors = append(result.Factors, factor)
		totalWeight += factor.Weight
		weightedSum += factor.WeightedScore

		// Collect warnings
		if factor.Status == "WARNING" || factor.Status == "BAD" {
			result.Warnings = append(result.Warnings, factor.Details)
		}
	}

	// Calculate overall score (0-100)
	if totalWeight > 0 {
		result.OverallScore = (weightedSum / totalWeight) * 100
	}

	// Determine risk level
	result.RiskLevel = h.calculateRiskLevel(result.OverallScore, factors)

	return result
}

// analyzeKeyStrength evaluates the cryptographic key strength
func (h *HeuristicAnalyzer) analyzeKeyStrength(cert *models.CertificateInfo) HeuristicFactor {
	factor := HeuristicFactor{
		Name:   "Key Strength",
		Weight: h.Weights.KeyStrength,
	}

	keySize := cert.KeySize
	algo := cert.PublicKeyAlgorithm

	switch {
	case strings.Contains(algo, "ECDSA"):
		// ECDSA keys are smaller but equally secure
		switch {
		case keySize >= 384:
			factor.Score = 1.0
			factor.Status = "GOOD"
			factor.Details = "Strong ECDSA key (P-384 or higher)"
		case keySize >= 256:
			factor.Score = 0.9
			factor.Status = "GOOD"
			factor.Details = "Good ECDSA key (P-256)"
		default:
			factor.Score = 0.3
			factor.Status = "BAD"
			factor.Details = "Weak ECDSA key size"
		}
	case strings.Contains(algo, "RSA"):
		switch {
		case keySize >= 4096:
			factor.Score = 1.0
			factor.Status = "GOOD"
			factor.Details = "Very strong RSA key (4096-bit)"
		case keySize >= 2048:
			factor.Score = 0.8
			factor.Status = "GOOD"
			factor.Details = "Standard RSA key (2048-bit)"
		case keySize >= 1024:
			factor.Score = 0.3
			factor.Status = "WARNING"
			factor.Details = "Weak RSA key (1024-bit) - deprecated"
		default:
			factor.Score = 0.0
			factor.Status = "BAD"
			factor.Details = "Critically weak RSA key"
		}
	case strings.Contains(algo, "Ed25519"):
		factor.Score = 1.0
		factor.Status = "GOOD"
		factor.Details = "Modern Ed25519 key"
	default:
		factor.Score = 0.5
		factor.Status = "WARNING"
		factor.Details = "Unknown key algorithm"
	}

	factor.WeightedScore = factor.Score * factor.Weight
	return factor
}

// analyzeValidityPeriod checks if validity period is reasonable
func (h *HeuristicAnalyzer) analyzeValidityPeriod(cert *models.CertificateInfo) HeuristicFactor {
	factor := HeuristicFactor{
		Name:   "Validity Period",
		Weight: h.Weights.ValidityPeriod,
	}

	validityDays := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24

	switch {
	case validityDays <= 90:
		// Short-lived certs (Let's Encrypt style) are good
		factor.Score = 1.0
		factor.Status = "GOOD"
		factor.Details = "Short-lived certificate (≤90 days) - best practice"
	case validityDays <= 398:
		// Apple/Browser limit is 398 days
		factor.Score = 0.9
		factor.Status = "GOOD"
		factor.Details = "Standard validity period (≤398 days)"
	case validityDays <= 825:
		factor.Score = 0.7
		factor.Status = "WARNING"
		factor.Details = "Long validity period - consider shorter"
	default:
		factor.Score = 0.3
		factor.Status = "BAD"
		factor.Details = "Excessively long validity period"
	}

	factor.WeightedScore = factor.Score * factor.Weight
	return factor
}

// analyzeIssuerReputation checks if the issuer is well-known
func (h *HeuristicAnalyzer) analyzeIssuerReputation(cert *models.CertificateInfo) HeuristicFactor {
	factor := HeuristicFactor{
		Name:   "Issuer Reputation",
		Weight: h.Weights.IssuerReputation,
	}

	// Check for well-known CAs
	wellKnownCAs := map[string]float64{
		"digicert":              1.0,
		"let's encrypt":        1.0,
		"sectigo":              0.95,
		"godaddy":              0.9,
		"globalsign":           0.95,
		"comodo":               0.9,
		"entrust":              0.95,
		"geotrust":             0.9,
		"thawte":               0.85,
		"verisign":             0.9,
		"amazon":               0.95,
		"google trust services": 1.0,
		"cloudflare":           0.95,
		"microsoft":            0.9,
		"baltimore":            0.85,
		"isrg":                 1.0,
	}

	issuerLower := strings.ToLower(cert.Issuer)

	if cert.IsSelfSigned {
		factor.Score = 0.0
		factor.Status = "BAD"
		factor.Details = "Self-signed certificate - MITM indicator"
		factor.WeightedScore = factor.Score * factor.Weight
		return factor
	}

	for ca, score := range wellKnownCAs {
		if strings.Contains(issuerLower, ca) {
			factor.Score = score
			factor.Status = "GOOD"
			factor.Details = "Well-known CA: " + cert.Issuer
			factor.WeightedScore = factor.Score * factor.Weight
			return factor
		}
	}

	// Unknown issuer - suspicious
	factor.Score = 0.4
	factor.Status = "WARNING"
	factor.Details = "Unknown CA: " + cert.Issuer
	factor.WeightedScore = factor.Score * factor.Weight
	return factor
}

// analyzeChainDepth checks the certificate chain depth
func (h *HeuristicAnalyzer) analyzeChainDepth(cert *models.CertificateInfo) HeuristicFactor {
	factor := HeuristicFactor{
		Name:   "Chain Depth",
		Weight: h.Weights.ChainDepth,
	}

	depth := cert.ChainDepth

	switch {
	case depth == 1:
		// Self-signed or root only
		factor.Score = 0.2
		factor.Status = "WARNING"
		factor.Details = "No intermediate CA in chain"
	case depth == 2:
		// Leaf + Root (unusual but valid)
		factor.Score = 0.7
		factor.Status = "WARNING"
		factor.Details = "Short chain (no intermediate)"
	case depth == 3:
		// Standard: Leaf + Intermediate + Root
		factor.Score = 1.0
		factor.Status = "GOOD"
		factor.Details = "Standard chain depth"
	case depth == 4:
		// Leaf + 2 Intermediates + Root
		factor.Score = 0.9
		factor.Status = "GOOD"
		factor.Details = "Standard chain depth with multiple intermediates"
	default:
		factor.Score = 0.6
		factor.Status = "WARNING"
		factor.Details = "Unusual chain depth"
	}

	factor.WeightedScore = factor.Score * factor.Weight
	return factor
}

// analyzeSignatureAlgorithm evaluates the signature algorithm
func (h *HeuristicAnalyzer) analyzeSignatureAlgorithm(cert *models.CertificateInfo) HeuristicFactor {
	factor := HeuristicFactor{
		Name:   "Signature Algorithm",
		Weight: h.Weights.SignatureAlgo,
	}

	algo := strings.ToLower(cert.SignatureAlgorithm)

	switch {
	case strings.Contains(algo, "sha384") || strings.Contains(algo, "sha512"):
		factor.Score = 1.0
		factor.Status = "GOOD"
		factor.Details = "Strong signature algorithm"
	case strings.Contains(algo, "sha256"):
		factor.Score = 0.95
		factor.Status = "GOOD"
		factor.Details = "Standard SHA-256 signature"
	case strings.Contains(algo, "sha1"):
		factor.Score = 0.2
		factor.Status = "BAD"
		factor.Details = "Deprecated SHA-1 signature - security risk"
	case strings.Contains(algo, "md5"):
		factor.Score = 0.0
		factor.Status = "BAD"
		factor.Details = "Broken MD5 signature - critical security risk"
	case strings.Contains(algo, "ed25519"):
		factor.Score = 1.0
		factor.Status = "GOOD"
		factor.Details = "Modern Ed25519 signature"
	default:
		factor.Score = 0.5
		factor.Status = "WARNING"
		factor.Details = "Unknown signature algorithm"
	}

	factor.WeightedScore = factor.Score * factor.Weight
	return factor
}

// analyzeSANConfiguration checks Subject Alternative Names
func (h *HeuristicAnalyzer) analyzeSANConfiguration(cert *models.CertificateInfo) HeuristicFactor {
	factor := HeuristicFactor{
		Name:   "SAN Configuration",
		Weight: h.Weights.SANConfiguration,
	}

	sanCount := len(cert.SANs)

	switch {
	case sanCount == 0:
		factor.Score = 0.5
		factor.Status = "WARNING"
		factor.Details = "No SANs - using CN only (deprecated)"
	case sanCount <= 3:
		factor.Score = 1.0
		factor.Status = "GOOD"
		factor.Details = "Reasonable SAN count"
	case sanCount <= 10:
		factor.Score = 0.9
		factor.Status = "GOOD"
		factor.Details = "Multiple SANs configured"
	case sanCount <= 50:
		factor.Score = 0.7
		factor.Status = "WARNING"
		factor.Details = "Many SANs - could be shared certificate"
	default:
		factor.Score = 0.5
		factor.Status = "WARNING"
		factor.Details = "Excessive SANs - unusual certificate"
	}

	// Check for wildcard
	for _, san := range cert.SANs {
		if strings.HasPrefix(san, "*.") {
			factor.Details += " (includes wildcard)"
			break
		}
	}

	factor.WeightedScore = factor.Score * factor.Weight
	return factor
}

// analyzeCertificateAge checks how long the certificate has been in use
func (h *HeuristicAnalyzer) analyzeCertificateAge(cert *models.CertificateInfo) HeuristicFactor {
	factor := HeuristicFactor{
		Name:   "Certificate Age",
		Weight: h.Weights.CertificateAge,
	}

	age := time.Since(cert.NotBefore).Hours() / 24

	switch {
	case age < 0:
		factor.Score = 0.0
		factor.Status = "BAD"
		factor.Details = "Certificate not yet valid"
	case age < 1:
		factor.Score = 0.7
		factor.Status = "WARNING"
		factor.Details = "Very new certificate (< 1 day)"
	case age < 7:
		factor.Score = 0.85
		factor.Status = "GOOD"
		factor.Details = "New certificate (< 1 week)"
	case age < 30:
		factor.Score = 0.95
		factor.Status = "GOOD"
		factor.Details = "Recent certificate (< 1 month)"
	default:
		factor.Score = 1.0
		factor.Status = "GOOD"
		factor.Details = "Established certificate"
	}

	factor.WeightedScore = factor.Score * factor.Weight
	return factor
}

// analyzeExpiryProximity checks how close the certificate is to expiring
func (h *HeuristicAnalyzer) analyzeExpiryProximity(cert *models.CertificateInfo) HeuristicFactor {
	factor := HeuristicFactor{
		Name:   "Expiry Proximity",
		Weight: h.Weights.ExpiryProximity,
	}

	daysLeft := cert.DaysUntilExpiry

	switch {
	case daysLeft < 0:
		factor.Score = 0.0
		factor.Status = "BAD"
		factor.Details = "Certificate has expired"
	case daysLeft < 7:
		factor.Score = 0.3
		factor.Status = "BAD"
		factor.Details = "Certificate expiring very soon"
	case daysLeft < 14:
		factor.Score = 0.5
		factor.Status = "WARNING"
		factor.Details = "Certificate expiring within 2 weeks"
	case daysLeft < 30:
		factor.Score = 0.7
		factor.Status = "WARNING"
		factor.Details = "Certificate expiring within 1 month"
	default:
		factor.Score = 1.0
		factor.Status = "GOOD"
		factor.Details = "Certificate has healthy validity period"
	}

	factor.WeightedScore = factor.Score * factor.Weight
	return factor
}

// calculateRiskLevel determines the overall risk level
func (h *HeuristicAnalyzer) calculateRiskLevel(score float64, factors []HeuristicFactor) string {
	// Check for any critical failures
	for _, factor := range factors {
		if factor.Status == "BAD" && factor.Score == 0.0 {
			return "CRITICAL"
		}
	}

	// Base on overall score
	switch {
	case score >= 80:
		return "LOW"
	case score >= 60:
		return "MEDIUM"
	case score >= 40:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}

// NormalizeScore normalizes a value to 0-1 range using sigmoid-like function
func NormalizeScore(value, optimal, tolerance float64) float64 {
	diff := math.Abs(value - optimal)
	return math.Exp(-diff / tolerance)
}
