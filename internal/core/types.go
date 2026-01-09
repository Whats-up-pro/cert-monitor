// Package core provides the core domain types for Cert-Monitor v2.0
// This package defines all data structures used across the verification system.
package core

import (
	"cert-monitor/internal/models"
	"crypto/x509"
	"time"
)

// ========================================
// REQUEST/RESPONSE TYPES
// ========================================

// VerificationRequest represents a client request to verify a domain's certificate
type VerificationRequest struct {
	// Domain to verify (e.g., "google.com")
	Domain string `json:"domain"`

	// Client's observed certificate fingerprint (SHA-256)
	ClientCertFingerprint string `json:"client_fingerprint"`

	// Client's IP address for geo-aware validation
	ClientIP string `json:"client_ip,omitempty"`

	// Unique request identifier for tracing
	RequestID string `json:"request_id"`

	// Timestamp when the request was created
	Timestamp int64 `json:"timestamp"`

	// Full certificate chain from client (base64 encoded DER)
	CertificateChain []string `json:"certificate_chain,omitempty"`
}

// VerificationResponse contains the complete verification result
type VerificationResponse struct {
	// Final verdict: SAFE, MITM_DETECTED, SUSPICIOUS, ERROR
	Verdict Verdict `json:"verdict"`

	// Overall confidence score (0.0 - 1.0)
	Confidence float64 `json:"confidence"`

	// Multi-dimensional security score (0.0 - 100.0)
	SecurityScore float64 `json:"security_score"`

	// ML-based anomaly score (0.0 - 1.0), higher = more anomalous
	AnomalyScore float64 `json:"anomaly_score"`

	// Results from each validation dimension
	Dimensions []DimensionResult `json:"dimensions"`

	// Cryptographic attestation proof
	Attestation *AttestationProof `json:"attestation,omitempty"`

	// Whether this result came from cache
	CachedResult bool `json:"cached"`

	// Total verification latency in milliseconds
	LatencyMs int64 `json:"latency_ms"`

	// Request ID for correlation
	RequestID string `json:"request_id"`

	// Timestamp of response
	Timestamp int64 `json:"timestamp"`

	// Human-readable message
	Message string `json:"message"`

	// Detailed error if any
	Error string `json:"error,omitempty"`
}

// ========================================
// VERDICT TYPES
// ========================================

// Verdict represents the final verification decision
type Verdict string

const (
	// VerdictSafe indicates no MITM attack detected
	VerdictSafe Verdict = "SAFE"

	// VerdictMITMDetected indicates active MITM attack detected
	VerdictMITMDetected Verdict = "MITM_DETECTED"

	// VerdictSuspicious indicates potential issues but not confirmed attack
	VerdictSuspicious Verdict = "SUSPICIOUS"

	// VerdictError indicates verification could not complete
	VerdictError Verdict = "ERROR"

	// VerdictCached indicates result from TOFU cache
	VerdictCached Verdict = "CACHED_SAFE"
)

// ========================================
// MULTI-DIMENSIONAL VALIDATION
// ========================================

// ValidationDimension represents the type of validation performed
type ValidationDimension string

const (
	// DimFingerprint - SHA-256 fingerprint comparison
	DimFingerprint ValidationDimension = "FINGERPRINT"

	// DimCTPresence - Certificate Transparency log presence
	DimCTPresence ValidationDimension = "CT_PRESENCE"

	// DimOCSPStatus - Online Certificate Status Protocol check
	DimOCSPStatus ValidationDimension = "OCSP_STATUS"

	// DimDNSCAA - DNS Certification Authority Authorization
	DimDNSCAA ValidationDimension = "DNS_CAA"

	// DimHistorical - TOFU cache comparison
	DimHistorical ValidationDimension = "HISTORICAL"

	// DimChainValidity - Certificate chain validation
	DimChainValidity ValidationDimension = "CHAIN_VALIDITY"

	// DimMLAnomaly - Machine learning anomaly detection
	DimMLAnomaly ValidationDimension = "ML_ANOMALY"
)

// DimensionResult contains the result of a single validation dimension
type DimensionResult struct {
	// Dimension type
	Dimension ValidationDimension `json:"dimension"`

	// Status: PASS, FAIL, WARNING, UNKNOWN, SKIPPED
	Status DimensionStatus `json:"status"`

	// Score for this dimension (0.0 - 1.0)
	Score float64 `json:"score"`

	// Weight used in final calculation
	Weight float64 `json:"weight"`

	// Human-readable details
	Details string `json:"details"`

	// Time taken for this dimension check (ms)
	LatencyMs int64 `json:"latency_ms"`
}

// DimensionStatus represents the status of a dimension check
type DimensionStatus string

const (
	StatusPass    DimensionStatus = "PASS"
	StatusFail    DimensionStatus = "FAIL"
	StatusWarning DimensionStatus = "WARNING"
	StatusUnknown DimensionStatus = "UNKNOWN"
	StatusSkipped DimensionStatus = "SKIPPED"
)

// DimensionWeights defines the default weights for each validation dimension
var DimensionWeights = map[ValidationDimension]float64{
	DimFingerprint:   0.30, // Highest weight - direct comparison
	DimCTPresence:    0.25, // CT is industry standard
	DimOCSPStatus:    0.15, // Real-time revocation
	DimDNSCAA:        0.10, // CAA records
	DimHistorical:    0.10, // TOFU cache
	DimChainValidity: 0.05, // Chain validation
	DimMLAnomaly:     0.05, // ML detection
}

// ========================================
// CERTIFICATE TYPES
// ========================================

// CertificateInfo contains extracted certificate information
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

// ========================================
// CT LOG TYPES
// ========================================

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

// ========================================
// OCSP TYPES
// ========================================

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

// ========================================
// CONSENSUS TYPES
// ========================================

// AgentResponse represents a verification response from a single agent
type AgentResponse struct {
	// Agent identifier
	AgentID string `json:"agent_id"`

	// Geographic region of the agent
	Region string `json:"region"`

	// Certificate fingerprint observed by this agent
	ObservedFingerprint string `json:"observed_fingerprint"`

	// Full verification response
	Response *VerificationResponse `json:"response"`

	// Response timestamp
	Timestamp int64 `json:"timestamp"`

	// Attestation proof
	Attestation *AttestationProof `json:"attestation"`

	// Error if this agent failed
	Error string `json:"error,omitempty"`
}

// ConsensusResult represents the result of multi-agent consensus
type ConsensusResult struct {
	// Final aggregated verdict
	Verdict Verdict `json:"verdict"`

	// Number of agents that agreed
	AgreementCount int `json:"agreement_count"`

	// Total number of agents queried
	TotalAgents int `json:"total_agents"`

	// Individual agent responses
	AgentResponses []*AgentResponse `json:"agent_responses"`

	// Consensus achieved
	ConsensusAchieved bool `json:"consensus_achieved"`

	// Consensus message
	Message string `json:"message"`
}

// ========================================
// ATTESTATION TYPES
// ========================================

// AttestationProof provides cryptographic proof of agent integrity
type AttestationProof struct {
	// Agent identifier
	AgentID string `json:"agent_id"`

	// Agent version
	AgentVersion string `json:"agent_version"`

	// Timestamp of attestation
	Timestamp int64 `json:"timestamp"`

	// Hash of the verification data
	DataHash string `json:"data_hash"`

	// Nonce for replay protection
	Nonce string `json:"nonce"`

	// Ed25519 signature of the attestation
	Signature string `json:"signature"`

	// Agent's public key (for verification)
	PublicKey string `json:"public_key"`
}

// ========================================
// CACHE TYPES
// ========================================

// CacheEntry represents a TOFU cache entry
type CacheEntry struct {
	// Domain name
	Domain string `json:"domain"`

	// Trusted fingerprint
	Fingerprint string `json:"fingerprint"`

	// Full certificate info
	CertInfo *models.CertificateInfo `json:"cert_info"`

	// When this entry was created
	CreatedAt time.Time `json:"created_at"`

	// When this entry expires
	ExpiresAt time.Time `json:"expires_at"`

	// Number of times this entry has been verified
	VerificationCount int `json:"verification_count"`

	// Last verification time
	LastVerified time.Time `json:"last_verified"`

	// Security score from last verification
	SecurityScore float64 `json:"security_score"`
}

// ========================================
// ML ANOMALY TYPES
// ========================================

// MLFeatures contains features extracted for ML analysis
type MLFeatures struct {
	// Certificate age in days
	CertAgeInDays float64 `json:"cert_age_days"`

	// Days until expiry
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

// ========================================
// ERROR TYPES
// ========================================

// VerificationError represents a verification error
type VerificationError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// Error codes
const (
	ErrCodeConnectionFailed  = "CONNECTION_FAILED"
	ErrCodeCertNotFound      = "CERT_NOT_FOUND"
	ErrCodeCTQueryFailed     = "CT_QUERY_FAILED"
	ErrCodeOCSPFailed        = "OCSP_FAILED"
	ErrCodeConsensusFailed   = "CONSENSUS_FAILED"
	ErrCodeTimeout           = "TIMEOUT"
	ErrCodeInvalidRequest    = "INVALID_REQUEST"
	ErrCodeInternalError     = "INTERNAL_ERROR"
)
