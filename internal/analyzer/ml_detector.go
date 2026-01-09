// Package analyzer provides ML-based anomaly detection for certificates
package analyzer

import (
	"cert-monitor/internal/models"
	"math"
	"strings"
	"time"
)

// MLAnomalyDetector performs ML-based anomaly detection on certificates
// This is a rule-based implementation that mimics ML behavior
// For production, this would load an ONNX model
type MLAnomalyDetector struct {
	// Model version
	ModelVersion string

	// Feature statistics for normalization (from training data)
	FeatureStats FeatureStatistics

	// Thresholds for anomaly detection
	Thresholds AnomalyThresholds
}

// FeatureStatistics contains mean and std for feature normalization
type FeatureStatistics struct {
	CertAgeMean          float64
	CertAgeStd           float64
	ValidityPeriodMean   float64
	ValidityPeriodStd    float64
	KeySizeMean          float64
	KeySizeStd           float64
	SANCountMean         float64
	SANCountStd          float64
	ChainDepthMean       float64
	ChainDepthStd        float64
}

// AnomalyThresholds defines thresholds for anomaly detection
type AnomalyThresholds struct {
	HighAnomalyThreshold float64
	MedAnomalyThreshold  float64
	MinValidityDays      float64
	MaxValidityDays      float64
	MinKeySize           int
}

// DefaultFeatureStats returns typical feature statistics
func DefaultFeatureStats() FeatureStatistics {
	return FeatureStatistics{
		CertAgeMean:        45.0,
		CertAgeStd:         30.0,
		ValidityPeriodMean: 90.0,
		ValidityPeriodStd:  60.0,
		KeySizeMean:        2048.0,
		KeySizeStd:         512.0,
		SANCountMean:       3.0,
		SANCountStd:        2.0,
		ChainDepthMean:     3.0,
		ChainDepthStd:      1.0,
	}
}

// DefaultThresholds returns default anomaly thresholds
func DefaultThresholds() AnomalyThresholds {
	return AnomalyThresholds{
		HighAnomalyThreshold: 0.7,
		MedAnomalyThreshold:  0.5,
		MinValidityDays:      1,
		MaxValidityDays:      825,
		MinKeySize:           2048,
	}
}

// NewMLAnomalyDetector creates a new ML anomaly detector
func NewMLAnomalyDetector() *MLAnomalyDetector {
	return &MLAnomalyDetector{
		ModelVersion: "2.0.0-rule-based",
		FeatureStats: DefaultFeatureStats(),
		Thresholds:   DefaultThresholds(),
	}
}

// ExtractFeatures extracts ML features from a certificate
func (d *MLAnomalyDetector) ExtractFeatures(cert *models.CertificateInfo) *models.MLFeatures {
	now := time.Now()

	// Certificate age in days
	certAge := now.Sub(cert.NotBefore).Hours() / 24

	// Days to expiry
	daysToExpiry := cert.NotAfter.Sub(now).Hours() / 24

	// Validity period in days
	validityPeriod := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24

	// Normalize key size
	keySize := float64(cert.KeySize)
	keySizeNorm := d.normalize(keySize, d.FeatureStats.KeySizeMean, d.FeatureStats.KeySizeStd)

	// SAN count
	sanCount := float64(len(cert.SANs))

	// Chain depth
	chainDepth := float64(cert.ChainDepth)

	// Issuer reputation (1.0 = known, 0.0 = unknown)
	issuerRep := 0.0
	if isKnownIssuer(cert.Issuer) {
		issuerRep = 1.0
	}

	// Self-signed
	selfSigned := 0.0
	if cert.IsSelfSigned {
		selfSigned = 1.0
	}

	// Signature algorithm score
	sigAlgoScore := signatureAlgorithmScore(cert.SignatureAlgorithm)

	// Has embedded SCT (simplified check)
	hasEmbeddedSCT := 0.0
	// In production, would parse X509v3 extensions

	return &models.MLFeatures{
		CertAgeInDays:           certAge,
		DaysToExpiry:            daysToExpiry,
		ValidityPeriodDays:      validityPeriod,
		KeySizeNormalized:       keySizeNorm,
		SANCount:                sanCount,
		ChainDepth:              chainDepth,
		IssuerReputation:        issuerRep,
		IsSelfSigned:            selfSigned,
		SignatureAlgorithmScore: sigAlgoScore,
		HasEmbeddedSCT:          hasEmbeddedSCT,
	}
}

// Predict calculates anomaly score for a certificate
func (d *MLAnomalyDetector) Predict(cert *models.CertificateInfo) *models.MLPrediction {
	features := d.ExtractFeatures(cert)

	// Calculate individual anomaly scores
	scores := make(map[string]float64)

	// Self-signed is highly anomalous for public websites
	scores["self_signed"] = features.IsSelfSigned * 0.5

	// Unknown issuer is suspicious
	scores["issuer_unknown"] = (1.0 - features.IssuerReputation) * 0.3

	// Weak signature algorithm
	scores["weak_signature"] = (1.0 - features.SignatureAlgorithmScore) * 0.2

	// Key size too small
	if features.KeySizeNormalized < 0.5 {
		scores["weak_key"] = (0.5 - features.KeySizeNormalized) * 0.3
	}

	// Very new certificate (could be freshly generated for MITM)
	if features.CertAgeInDays < 1 {
		scores["too_new"] = 0.4
	} else if features.CertAgeInDays < 7 {
		scores["very_new"] = 0.2
	}

	// Expired or about to expire
	if features.DaysToExpiry < 0 {
		scores["expired"] = 0.5
	} else if features.DaysToExpiry < 7 {
		scores["expiring_soon"] = 0.3
	}

	// Unusual validity period
	if features.ValidityPeriodDays < float64(d.Thresholds.MinValidityDays) {
		scores["short_validity"] = 0.3
	} else if features.ValidityPeriodDays > float64(d.Thresholds.MaxValidityDays) {
		scores["long_validity"] = 0.2
	}

	// Short chain (no intermediate)
	if features.ChainDepth < 2 {
		scores["short_chain"] = 0.3
	}

	// Too many SANs (unusual)
	if features.SANCount > 50 {
		scores["excessive_sans"] = 0.1
	}

	// Calculate total anomaly score
	var totalScore float64
	for _, score := range scores {
		totalScore += score
	}

	// Normalize to 0-1 using sigmoid
	anomalyScore := sigmoid(totalScore - 0.5)

	// Calculate confidence based on feature availability
	confidence := d.calculateConfidence(features)

	// Get top contributing features
	topFeatures := d.getTopContributions(scores, features)

	return &models.MLPrediction{
		AnomalyScore: anomalyScore,
		Confidence:   confidence,
		TopFeatures:  topFeatures,
		ModelVersion: d.ModelVersion,
	}
}

// normalize normalizes a value using z-score normalization
func (d *MLAnomalyDetector) normalize(value, mean, std float64) float64 {
	if std == 0 {
		return 0
	}
	return (value - mean) / std
}

// calculateConfidence calculates prediction confidence
func (d *MLAnomalyDetector) calculateConfidence(features *models.MLFeatures) float64 {
	// Higher confidence when we have more data
	confidence := 0.6 // Base confidence

	// More confidence if we know the issuer
	if features.IssuerReputation > 0 {
		confidence += 0.15
	}

	// More confidence with standard chain depth
	if features.ChainDepth >= 2 && features.ChainDepth <= 4 {
		confidence += 0.1
	}

	// More confidence with reasonable key size
	if features.KeySizeNormalized > 0.5 {
		confidence += 0.1
	}

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// getTopContributions returns the top contributing features to the anomaly score
func (d *MLAnomalyDetector) getTopContributions(scores map[string]float64, features *models.MLFeatures) []models.FeatureContribution {
	contributions := make([]models.FeatureContribution, 0)

	// Map score names to feature values
	featureValues := map[string]float64{
		"self_signed":    features.IsSelfSigned,
		"issuer_unknown": 1.0 - features.IssuerReputation,
		"weak_signature": 1.0 - features.SignatureAlgorithmScore,
		"weak_key":       features.KeySizeNormalized,
		"too_new":        features.CertAgeInDays,
		"very_new":       features.CertAgeInDays,
		"expired":        features.DaysToExpiry,
		"expiring_soon":  features.DaysToExpiry,
		"short_validity": features.ValidityPeriodDays,
		"long_validity":  features.ValidityPeriodDays,
		"short_chain":    features.ChainDepth,
		"excessive_sans": features.SANCount,
	}

	for name, contribution := range scores {
		if contribution > 0 {
			value := featureValues[name]
			contributions = append(contributions, models.FeatureContribution{
				FeatureName:  name,
				Value:        value,
				Contribution: contribution,
			})
		}
	}

	// Sort by contribution (descending) - simple bubble sort for small array
	for i := 0; i < len(contributions); i++ {
		for j := i + 1; j < len(contributions); j++ {
			if contributions[j].Contribution > contributions[i].Contribution {
				contributions[i], contributions[j] = contributions[j], contributions[i]
			}
		}
	}

	// Return top 5
	if len(contributions) > 5 {
		return contributions[:5]
	}
	return contributions
}

// sigmoid applies sigmoid function
func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x*4)) // Scale factor of 4 for steeper curve
}

// isKnownIssuer checks if issuer is a known CA
func isKnownIssuer(issuer string) bool {
	knownCAs := []string{
		"digicert", "let's encrypt", "sectigo", "godaddy",
		"globalsign", "comodo", "entrust", "geotrust",
		"thawte", "verisign", "amazon", "google trust",
		"cloudflare", "microsoft", "baltimore", "isrg",
	}

	issuerLower := strings.ToLower(issuer)
	for _, ca := range knownCAs {
		if strings.Contains(issuerLower, ca) {
			return true
		}
	}
	return false
}

// signatureAlgorithmScore returns a score for signature algorithm strength
func signatureAlgorithmScore(algo string) float64 {
	algoLower := strings.ToLower(algo)

	switch {
	case strings.Contains(algoLower, "sha512"):
		return 1.0
	case strings.Contains(algoLower, "sha384"):
		return 0.95
	case strings.Contains(algoLower, "sha256"):
		return 0.9
	case strings.Contains(algoLower, "sha1"):
		return 0.3 // Deprecated
	case strings.Contains(algoLower, "md5"):
		return 0.0 // Broken
	case strings.Contains(algoLower, "ed25519"):
		return 1.0
	default:
		return 0.5
	}
}

// MLScoreToSecurityImpact converts ML anomaly score to security impact
func MLScoreToSecurityImpact(score float64) string {
	switch {
	case score >= 0.8:
		return "CRITICAL - High likelihood of malicious certificate"
	case score >= 0.6:
		return "HIGH - Significant anomalies detected"
	case score >= 0.4:
		return "MEDIUM - Some unusual characteristics"
	case score >= 0.2:
		return "LOW - Minor deviations from typical certificates"
	default:
		return "MINIMAL - Certificate appears normal"
	}
}
