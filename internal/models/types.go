// Package models provides shared types without circular dependencies
package models

import (
	"crypto/x509"
	"time"
)

// CertificateInfo contains extracted certificate information
// This is placed in models package to avoid import cycles
type CertificateInfo struct {
	// SHA-256 fingerprint of the certificate
	Fingerprint string `json:"fingerprint"`

	// SHA-256 fingerprint of the public key (for pinning)
	PublicKeyFingerprint string `json:"public_key_fingerprint"`

	// Subject Common Name
	Subject string `json:"subject"`

	// Issuer Common Name
	Issuer string `json:"issuer"`

	// Certificate serial number (hex encoded)
	SerialNumber string `json:"serial_number"`

	// Subject Alternative Names
	SANs []string `json:"sans"`

	// Not Before date
	NotBefore time.Time `json:"not_before"`

	// Not After date (expiry)
	NotAfter time.Time `json:"not_after"`

	// Signature algorithm
	SignatureAlgorithm string `json:"signature_algorithm"`

	// Public key algorithm
	PublicKeyAlgorithm string `json:"public_key_algorithm"`

	// Key size in bits
	KeySize int `json:"key_size"`

	// Is self-signed
	IsSelfSigned bool `json:"is_self_signed"`

	// Certificate chain depth
	ChainDepth int `json:"chain_depth"`

	// Days until expiry
	DaysUntilExpiry int `json:"days_until_expiry"`

	// Raw certificate (DER encoded, base64)
	RawCertificate string `json:"raw_certificate,omitempty"`

	// Parsed certificate (not serialized)
	ParsedCert *x509.Certificate `json:"-"`
}

// MLFeatures contains features extracted for ML analysis
type MLFeatures struct {
	// Certificate age in days
	CertAgeInDays float64 `json:"cert_age_days"`

	// Days to expiry
	DaysToExpiry float64 `json:"days_to_expiry"`

	// Validity period length in days
	ValidityPeriodDays float64 `json:"validity_period_days"`

	// Key size (normalized)
	KeySizeNormalized float64 `json:"key_size_normalized"`

	// Number of SANs
	SANCount float64 `json:"san_count"`

	// Chain depth
	ChainDepth float64 `json:"chain_depth"`

	// Issuer is well-known (1.0 = yes, 0.0 = no)
	IssuerReputation float64 `json:"issuer_reputation"`

	// Self-signed flag (1.0 = yes, 0.0 = no)
	IsSelfSigned float64 `json:"is_self_signed"`

	// Signature algorithm score (higher = better)
	SignatureAlgorithmScore float64 `json:"sig_algo_score"`

	// Has CT SCTs embedded (1.0 = yes, 0.0 = no)
	HasEmbeddedSCT float64 `json:"has_embedded_sct"`
}

// MLPrediction contains ML model output
type MLPrediction struct {
	// Anomaly score (0.0 - 1.0)
	AnomalyScore float64 `json:"anomaly_score"`

	// Confidence in the prediction
	Confidence float64 `json:"confidence"`

	// Top contributing features
	TopFeatures []FeatureContribution `json:"top_features"`

	// Model version used
	ModelVersion string `json:"model_version"`
}

// FeatureContribution shows how much each feature contributed
type FeatureContribution struct {
	FeatureName  string  `json:"feature_name"`
	Value        float64 `json:"value"`
	Contribution float64 `json:"contribution"`
}

// CertificateChain represents a full certificate chain
type CertificateChain struct {
	// Leaf certificate (end-entity)
	Leaf *CertificateInfo `json:"leaf"`

	// Intermediate certificates
	Intermediates []*CertificateInfo `json:"intermediates"`

	// Root certificate
	Root *CertificateInfo `json:"root,omitempty"`

	// Full chain fingerprints
	ChainFingerprints []string `json:"chain_fingerprints"`
}

// CTLogResult represents the result of a CT log query
type CTLogResult struct {
	// Whether certificate was found in CT logs
	Found bool `json:"found"`

	// Number of CT logs certificate was found in
	LogCount int `json:"log_count"`

	// Names of CT logs where certificate was found
	LogNames []string `json:"log_names"`

	// SCT (Signed Certificate Timestamp) data
	SCTs []*SCTInfo `json:"scts,omitempty"`

	// Error message if any
	Error string `json:"error,omitempty"`
}

// SCTInfo contains Signed Certificate Timestamp information
type SCTInfo struct {
	LogID     string    `json:"log_id"`
	Timestamp time.Time `json:"timestamp"`
	Signature string    `json:"signature"`
}

// OCSPResult represents the result of an OCSP check
type OCSPResult struct {
	// Status: Good, Revoked, Unknown
	Status OCSPStatus `json:"status"`

	// When the response was produced
	ProducedAt time.Time `json:"produced_at"`

	// When this response was last updated
	ThisUpdate time.Time `json:"this_update"`

	// When the next update is expected
	NextUpdate time.Time `json:"next_update"`

	// Revocation time (if revoked)
	RevokedAt *time.Time `json:"revoked_at,omitempty"`

	// Revocation reason
	RevocationReason string `json:"revocation_reason,omitempty"`

	// Error message if any
	Error string `json:"error,omitempty"`
}

// OCSPStatus represents OCSP response status
type OCSPStatus string

const (
	OCSPGood    OCSPStatus = "GOOD"
	OCSPRevoked OCSPStatus = "REVOKED"
	OCSPUnknown OCSPStatus = "UNKNOWN"
	OCSPError   OCSPStatus = "ERROR"
)
