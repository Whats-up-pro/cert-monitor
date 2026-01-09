// Package core provides Byzantine Fault Tolerant consensus for multi-agent verification
package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// ConsensusEngine implements Byzantine Fault Tolerant consensus for verification
type ConsensusEngine struct {
	// List of verification agents
	Agents []AgentEndpoint

	// HTTP client for agent communication
	client *http.Client

	// Consensus threshold (default: 2/3 + 1)
	Threshold float64

	// Timeout for agent queries
	Timeout time.Duration

	// Local agent's private key for attestation
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey

	// Agent ID for this instance
	AgentID string
}

// AgentEndpoint represents a verification agent endpoint
type AgentEndpoint struct {
	ID       string `json:"id"`
	URL      string `json:"url"`
	Region   string `json:"region"`
	Priority int    `json:"priority"`
	Enabled  bool   `json:"enabled"`

	// Public key for verifying attestations
	PublicKey string `json:"public_key"`
}

// DefaultAgents returns a list of default agent endpoints (for demo)
func DefaultAgents() []AgentEndpoint {
	return []AgentEndpoint{
		{ID: "agent-us-west", URL: "http://localhost:8081", Region: "US-West", Priority: 1, Enabled: true},
		{ID: "agent-eu-central", URL: "http://localhost:8082", Region: "EU-Central", Priority: 2, Enabled: true},
		{ID: "agent-apac-sg", URL: "http://localhost:8083", Region: "APAC-Singapore", Priority: 3, Enabled: true},
	}
}

// NewConsensusEngine creates a new consensus engine
func NewConsensusEngine(agentID string, agents []AgentEndpoint) *ConsensusEngine {
	// Generate Ed25519 keypair for attestation
	pubKey, privKey, _ := ed25519.GenerateKey(nil)

	if agents == nil || len(agents) == 0 {
		agents = DefaultAgents()
	}

	return &ConsensusEngine{
		Agents:     agents,
		client:     &http.Client{Timeout: 15 * time.Second},
		Threshold:  0.67, // 2/3 majority
		Timeout:    10 * time.Second,
		privateKey: privKey,
		publicKey:  pubKey,
		AgentID:    agentID,
	}
}

// VerifyWithConsensus queries multiple agents and reaches consensus
func (c *ConsensusEngine) VerifyWithConsensus(ctx context.Context, req *VerificationRequest) *ConsensusResult {
	result := &ConsensusResult{
		AgentResponses: make([]*AgentResponse, 0),
	}

	// Query all agents in parallel
	var wg sync.WaitGroup
	responseChan := make(chan *AgentResponse, len(c.Agents))

	for _, agent := range c.Agents {
		if !agent.Enabled {
			continue
		}

		wg.Add(1)
		go func(agent AgentEndpoint) {
			defer wg.Done()
			resp := c.queryAgent(ctx, agent, req)
			responseChan <- resp
		}(agent)
	}

	// Wait for all responses
	go func() {
		wg.Wait()
		close(responseChan)
	}()

	// Collect responses
	for resp := range responseChan {
		result.AgentResponses = append(result.AgentResponses, resp)
		if resp.Error == "" {
			result.TotalAgents++
		}
	}

	// Analyze consensus
	result.Verdict, result.AgreementCount, result.ConsensusAchieved = c.analyzeConsensus(result.AgentResponses)
	result.Message = c.generateConsensusMessage(result)

	return result
}

// queryAgent queries a single verification agent
func (c *ConsensusEngine) queryAgent(ctx context.Context, agent AgentEndpoint, req *VerificationRequest) *AgentResponse {
	response := &AgentResponse{
		AgentID:   agent.ID,
		Region:    agent.Region,
		Timestamp: time.Now().Unix(),
	}

	// Marshal request
	reqBody, err := json.Marshal(req)
	if err != nil {
		response.Error = fmt.Sprintf("Failed to marshal request: %v", err)
		return response
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", agent.URL+"/api/v2/verify", 
		bytes.NewReader(reqBody))
	if err != nil {
		response.Error = fmt.Sprintf("Failed to create request: %v", err)
		return response
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Request-ID", req.RequestID)

	// Execute request
	httpResp, err := c.client.Do(httpReq)
	if err != nil {
		response.Error = fmt.Sprintf("Agent unreachable: %v", err)
		return response
	}
	defer httpResp.Body.Close()

	// Read response
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		response.Error = fmt.Sprintf("Failed to read response: %v", err)
		return response
	}

	// Parse response
	var verifyResp VerificationResponse
	if err := json.Unmarshal(body, &verifyResp); err != nil {
		response.Error = fmt.Sprintf("Failed to parse response: %v", err)
		return response
	}

	response.Response = &verifyResp
	response.ObservedFingerprint = c.extractFingerprint(&verifyResp)
	response.Attestation = verifyResp.Attestation

	return response
}

// extractFingerprint extracts the observed fingerprint from verification response
func (c *ConsensusEngine) extractFingerprint(resp *VerificationResponse) string {
	for _, dim := range resp.Dimensions {
		if dim.Dimension == DimFingerprint {
			// Extract from details (simplified)
			return dim.Details
		}
	}
	return ""
}

// analyzeConsensus determines consensus from agent responses
func (c *ConsensusEngine) analyzeConsensus(responses []*AgentResponse) (Verdict, int, bool) {
	if len(responses) == 0 {
		return VerdictError, 0, false
	}

	// Count verdicts
	verdictCounts := make(map[Verdict]int)
	fingerprintCounts := make(map[string]int)

	for _, resp := range responses {
		if resp.Error != "" || resp.Response == nil {
			continue
		}

		verdictCounts[resp.Response.Verdict]++
		if resp.ObservedFingerprint != "" {
			fingerprintCounts[resp.ObservedFingerprint]++
		}
	}

	totalValid := 0
	for _, count := range verdictCounts {
		totalValid += count
	}

	if totalValid == 0 {
		return VerdictError, 0, false
	}

	// Find majority verdict
	var majorityVerdict Verdict
	var majorityCount int

	for verdict, count := range verdictCounts {
		if count > majorityCount {
			majorityCount = count
			majorityVerdict = verdict
		}
	}

	// Check if consensus threshold is met
	consensusRatio := float64(majorityCount) / float64(totalValid)
	consensusAchieved := consensusRatio >= c.Threshold

	// Special case: any MITM detection should be taken seriously
	if verdictCounts[VerdictMITMDetected] > 0 {
		// If any agent detects MITM, we need strong consensus to override
		if verdictCounts[VerdictSafe] < verdictCounts[VerdictMITMDetected]*2 {
			return VerdictMITMDetected, verdictCounts[VerdictMITMDetected], true
		}
	}

	return majorityVerdict, majorityCount, consensusAchieved
}

// generateConsensusMessage creates a human-readable consensus message
func (c *ConsensusEngine) generateConsensusMessage(result *ConsensusResult) string {
	if result.TotalAgents == 0 {
		return "No agents were reachable"
	}

	validResponses := 0
	for _, resp := range result.AgentResponses {
		if resp.Error == "" {
			validResponses++
		}
	}

	if result.ConsensusAchieved {
		return fmt.Sprintf("Consensus achieved: %d/%d agents agree on verdict %s",
			result.AgreementCount, validResponses, result.Verdict)
	}

	return fmt.Sprintf("Consensus not achieved: only %d/%d agents agree (threshold: %.0f%%)",
		result.AgreementCount, validResponses, c.Threshold*100)
}

// CreateAttestation creates a cryptographic attestation proof
func (c *ConsensusEngine) CreateAttestation(dataHash string) *AttestationProof {
	timestamp := time.Now().Unix()
	nonce := generateNonce()

	// Create attestation data
	attestData := fmt.Sprintf("%s|%d|%s|%s", c.AgentID, timestamp, dataHash, nonce)
	attestHash := sha256.Sum256([]byte(attestData))

	// Sign with Ed25519
	signature := ed25519.Sign(c.privateKey, attestHash[:])

	return &AttestationProof{
		AgentID:      c.AgentID,
		AgentVersion: "2.0.0",
		Timestamp:    timestamp,
		DataHash:     dataHash,
		Nonce:        nonce,
		Signature:    base64.StdEncoding.EncodeToString(signature),
		PublicKey:    base64.StdEncoding.EncodeToString(c.publicKey),
	}
}

// VerifyAttestation verifies an attestation proof from another agent
func VerifyAttestation(attestation *AttestationProof) (bool, error) {
	if attestation == nil {
		return false, fmt.Errorf("attestation is nil")
	}

	// Decode public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(attestation.PublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key: %w", err)
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size")
	}

	pubKey := ed25519.PublicKey(pubKeyBytes)

	// Decode signature
	sigBytes, err := base64.StdEncoding.DecodeString(attestation.Signature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Reconstruct attestation data
	attestData := fmt.Sprintf("%s|%d|%s|%s", 
		attestation.AgentID, attestation.Timestamp, attestation.DataHash, attestation.Nonce)
	attestHash := sha256.Sum256([]byte(attestData))

	// Verify signature
	valid := ed25519.Verify(pubKey, attestHash[:], sigBytes)

	return valid, nil
}

// generateNonce creates a random nonce for replay protection
func generateNonce() string {
	nonce := make([]byte, 16)
	// In production, use crypto/rand
	for i := range nonce {
		nonce[i] = byte(time.Now().UnixNano() >> (i * 8))
	}
	return hex.EncodeToString(nonce)
}

// CalculateDataHash calculates hash of verification data for attestation
func CalculateDataHash(domain, fingerprint string, verdict Verdict) string {
	data := fmt.Sprintf("%s|%s|%s", domain, fingerprint, verdict)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// IsQuorumReached checks if quorum is reached for BFT
func (c *ConsensusEngine) IsQuorumReached(agreementCount, totalAgents int) bool {
	if totalAgents == 0 {
		return false
	}

	// BFT requires 2f+1 out of 3f+1 (where f is max faulty nodes)
	// For 3 agents, we need 2 to agree (can tolerate 1 faulty)
	// For 4 agents, we need 3 to agree (can tolerate 1 faulty)
	// General formula: need more than 2/3

	return float64(agreementCount)/float64(totalAgents) >= c.Threshold
}

// GetRequiredAgreement returns minimum agreements needed for consensus
func (c *ConsensusEngine) GetRequiredAgreement(totalAgents int) int {
	required := int(float64(totalAgents)*c.Threshold) + 1
	if required > totalAgents {
		return totalAgents
	}
	return required
}

// AgentHealthCheck performs health check on all agents
func (c *ConsensusEngine) AgentHealthCheck(ctx context.Context) map[string]bool {
	health := make(map[string]bool)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, agent := range c.Agents {
		wg.Add(1)
		go func(agent AgentEndpoint) {
			defer wg.Done()

			req, _ := http.NewRequestWithContext(ctx, "GET", agent.URL+"/api/v2/health", nil)
			resp, err := c.client.Do(req)

			mu.Lock()
			if err == nil && resp.StatusCode == http.StatusOK {
				health[agent.ID] = true
			} else {
				health[agent.ID] = false
			}
			mu.Unlock()

			if resp != nil {
				resp.Body.Close()
			}
		}(agent)
	}

	wg.Wait()
	return health
}
