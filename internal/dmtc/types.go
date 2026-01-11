// Package dmtc implements Decentralized Multi-Vantage Trust Consensus (DMTC)
// for SplitSight certificate verification system.
package dmtc

import (
	"crypto/ed25519"
	"time"
)

// VantagePoint represents a decentralized verification node in the DMTC network.
// Each vantage point observes certificates from a unique network perspective.
type VantagePoint struct {
	// Unique identifier for this vantage point
	ID string `json:"id"`

	// Network endpoint for verification requests
	Endpoint string `json:"endpoint"`

	// Autonomous System Number - for diversity checking
	ASN uint32 `json:"asn"`

	// ASN organization name
	ASNOrg string `json:"asn_org"`

	// ISO 3166-1 alpha-2 country code
	Country string `json:"country"`

	// Infrastructure provider (e.g., AWS, GCP, DigitalOcean, self-hosted)
	Provider string `json:"provider"`

	// Geographic region for coarse-grained diversity
	Region string `json:"region"`

	// Public key for signature verification (Ed25519)
	PublicKey ed25519.PublicKey `json:"public_key"`

	// Last health check timestamp
	LastHealthCheck time.Time `json:"last_health_check"`

	// Health status
	IsHealthy bool `json:"is_healthy"`

	// Response latency in milliseconds (rolling average)
	AvgLatencyMs int64 `json:"avg_latency_ms"`

	// Reputation score (0.0 - 1.0) based on historical accuracy
	Reputation float64 `json:"reputation"`

	// Registration timestamp
	RegisteredAt time.Time `json:"registered_at"`
}

// DiversityRequirements specifies the anti-collusion constraints for vantage selection.
type DiversityRequirements struct {
	// Minimum number of distinct ASNs required
	MinDistinctASNs int `json:"min_distinct_asns"`

	// Minimum number of distinct countries required
	MinDistinctCountries int `json:"min_distinct_countries"`

	// Minimum number of distinct providers required
	MinDistinctProviders int `json:"min_distinct_providers"`

	// Total number of vantage points to query
	TotalVantagePoints int `json:"total_vantage_points"`

	// Maximum vantage points from same ASN
	MaxPerASN int `json:"max_per_asn"`

	// Maximum vantage points from same country
	MaxPerCountry int `json:"max_per_country"`
}

// DefaultDiversityRequirements returns conservative anti-collusion defaults.
func DefaultDiversityRequirements() DiversityRequirements {
	return DiversityRequirements{
		MinDistinctASNs:      3,
		MinDistinctCountries: 2,
		MinDistinctProviders: 2,
		TotalVantagePoints:   5,
		MaxPerASN:            2,
		MaxPerCountry:        3,
	}
}

// DMTCRequest represents a verification request to the DMTC network.
type DMTCRequest struct {
	// Request identifier
	RequestID string `json:"request_id"`

	// Domain to verify
	Domain string `json:"domain"`

	// Client-observed certificate fingerprint
	ClientFingerprint string `json:"client_fingerprint"`

	// Diversity requirements for this request
	Diversity DiversityRequirements `json:"diversity"`

	// Consensus threshold (default: 0.67 for 2/3+1)
	ConsensusThreshold float64 `json:"consensus_threshold"`

	// Request timestamp
	Timestamp time.Time `json:"timestamp"`

	// Optional: specific vantage points to query (overrides random selection)
	PreferredVantageIDs []string `json:"preferred_vantage_ids,omitempty"`
}

// VantageObservation represents a single vantage point's certificate observation.
type VantageObservation struct {
	// Vantage point that made this observation
	VantageID string `json:"vantage_id"`

	// Observed certificate fingerprint (SHA-256)
	Fingerprint string `json:"fingerprint"`

	// Full certificate chain (DER-encoded, base64)
	CertificateChain []string `json:"certificate_chain,omitempty"`

	// Certificate issuer
	Issuer string `json:"issuer"`

	// Certificate subject
	Subject string `json:"subject"`

	// Certificate validity period
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`

	// Observation timestamp
	ObservedAt time.Time `json:"observed_at"`

	// Latency to fetch certificate (ms)
	LatencyMs int64 `json:"latency_ms"`

	// Error if observation failed
	Error string `json:"error,omitempty"`

	// Ed25519 signature over observation data
	Signature []byte `json:"signature"`
}

// DMTCVerdict represents the possible consensus outcomes.
type DMTCVerdict string

const (
	VerdictSafe         DMTCVerdict = "SAFE"
	VerdictMITMDetected DMTCVerdict = "MITM_DETECTED"
	VerdictSuspicious   DMTCVerdict = "SUSPICIOUS"
	VerdictNoConsensus  DMTCVerdict = "NO_CONSENSUS"
	VerdictError        DMTCVerdict = "ERROR"
)

// DMTCResponse represents the aggregated consensus result.
type DMTCResponse struct {
	// Request identifier
	RequestID string `json:"request_id"`

	// Final verdict from consensus
	Verdict DMTCVerdict `json:"verdict"`

	// Consensus achieved (≥ threshold agreement)
	ConsensusAchieved bool `json:"consensus_achieved"`

	// Number of agreeing vantage points
	AgreementCount int `json:"agreement_count"`

	// Total vantage points queried
	TotalQueried int `json:"total_queried"`

	// Agreement ratio
	AgreementRatio float64 `json:"agreement_ratio"`

	// Majority fingerprint (if consensus achieved)
	MajorityFingerprint string `json:"majority_fingerprint"`

	// Does majority match client observation?
	MatchesClient bool `json:"matches_client"`

	// All observations from vantage points
	Observations []VantageObservation `json:"observations"`

	// Diversity metrics achieved
	DiversityAchieved DiversityMetrics `json:"diversity_achieved"`

	// Aggregated threshold signature (proof of consensus)
	ThresholdSignature *ThresholdSignature `json:"threshold_signature,omitempty"`

	// Response timestamp
	Timestamp time.Time `json:"timestamp"`

	// Total verification latency
	TotalLatencyMs int64 `json:"total_latency_ms"`

	// Human-readable message
	Message string `json:"message"`
}

// DiversityMetrics reports the actual diversity of queried vantage points.
type DiversityMetrics struct {
	DistinctASNs      int      `json:"distinct_asns"`
	DistinctCountries int      `json:"distinct_countries"`
	DistinctProviders int      `json:"distinct_providers"`
	ASNList           []uint32 `json:"asn_list"`
	CountryList       []string `json:"country_list"`
	ProviderList      []string `json:"provider_list"`
}

// ThresholdSignature represents an aggregated BLS-style threshold signature.
// In this implementation, we use Ed25519 multi-signatures for simplicity.
type ThresholdSignature struct {
	// Threshold (k of n)
	Threshold int `json:"threshold"`
	TotalN    int `json:"total_n"`

	// Signers who contributed
	SignerIDs []string `json:"signer_ids"`

	// Message hash that was signed
	MessageHash []byte `json:"message_hash"`

	// Individual signatures (for Ed25519 multi-sig)
	Signatures []SignerSignature `json:"signatures"`

	// Aggregation timestamp
	AggregatedAt time.Time `json:"aggregated_at"`
}

// SignerSignature pairs a signer ID with their signature.
type SignerSignature struct {
	SignerID  string `json:"signer_id"`
	Signature []byte `json:"signature"`
}

// RegistryEntry represents a vantage point in the DHT registry.
type RegistryEntry struct {
	VantagePoint VantagePoint `json:"vantage_point"`

	// DHT node ID (consistent hash of VantagePoint.ID)
	NodeID []byte `json:"node_id"`

	// TTL for registry entry
	ExpiresAt time.Time `json:"expires_at"`

	// Proof of registration (signature by vantage point)
	RegistrationProof []byte `json:"registration_proof"`
}

// GeoAttackDetection holds information about potential geo-targeted attacks.
type GeoAttackDetection struct {
	// Is a geo-targeted attack suspected?
	Suspected bool `json:"suspected"`

	// Regions/Countries showing different certificates
	AffectedRegions []string `json:"affected_regions"`

	// ASNs showing different certificates
	AffectedASNs []uint32 `json:"affected_asns"`

	// Fingerprints observed in affected vs unaffected regions
	AffectedFingerprint   string `json:"affected_fingerprint"`
	UnaffectedFingerprint string `json:"unaffected_fingerprint"`

	// Confidence level (0.0 - 1.0)
	Confidence float64 `json:"confidence"`
}
