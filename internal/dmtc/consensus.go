// Package dmtc implements DMTC consensus with threshold signatures.
package dmtc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

// ConsensusEngine implements Byzantine Fault Tolerant consensus for DMTC.
type ConsensusEngine struct {
	registry *Registry
	selector *Selector
	client   *http.Client

	// Consensus threshold (default: 2/3 + 1)
	Threshold float64

	// Timeout for vantage point queries
	QueryTimeout time.Duration

	// Local signing key (for this agent if acting as vantage point)
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey

	// Agent ID
	AgentID string
}

// NewConsensusEngine creates a new DMTC consensus engine.
func NewConsensusEngine(agentID string, registry *Registry) *ConsensusEngine {
	// Generate or load signing keypair
	pub, priv, _ := ed25519.GenerateKey(nil)

	return &ConsensusEngine{
		registry:     registry,
		selector:     NewSelector(registry),
		client:       &http.Client{Timeout: 10 * time.Second},
		Threshold:    0.67, // 2/3 + 1 for BFT
		QueryTimeout: 5 * time.Second,
		privateKey:   priv,
		publicKey:    pub,
		AgentID:      agentID,
	}
}

// VerifyWithConsensus performs DMTC verification with multi-vantage consensus.
func (c *ConsensusEngine) VerifyWithConsensus(ctx context.Context, req *DMTCRequest) *DMTCResponse {
	startTime := time.Now()

	response := &DMTCResponse{
		RequestID:    req.RequestID,
		Observations: make([]VantageObservation, 0),
		Timestamp:    time.Now(),
	}

	// Select vantage points with diversity constraints
	selection, err := c.selector.Select(req.Diversity)
	if err != nil {
		response.Verdict = VerdictError
		response.Message = fmt.Sprintf("Failed to select vantage points: %v", err)
		return response
	}

	response.DiversityAchieved = selection.DiversityAchieved

	// Query all selected vantage points in parallel
	var wg sync.WaitGroup
	observations := make(chan VantageObservation, len(selection.VantagePoints))

	for _, vp := range selection.VantagePoints {
		wg.Add(1)
		go func(vp *VantagePoint) {
			defer wg.Done()
			obs := c.queryVantagePoint(ctx, vp, req.Domain)
			observations <- obs
		}(vp)
	}

	// Wait for all queries and close channel
	go func() {
		wg.Wait()
		close(observations)
	}()

	// Collect observations
	for obs := range observations {
		response.Observations = append(response.Observations, obs)
	}

	response.TotalQueried = len(selection.VantagePoints)

	// Analyze consensus
	c.analyzeConsensus(response, req.ClientFingerprint, req.ConsensusThreshold)

	// Create threshold signature if consensus achieved
	if response.ConsensusAchieved {
		response.ThresholdSignature = c.createThresholdSignature(response.Observations, response.MajorityFingerprint)
	}

	response.TotalLatencyMs = time.Since(startTime).Milliseconds()

	return response
}

// queryVantagePoint queries a single vantage point for certificate observation.
func (c *ConsensusEngine) queryVantagePoint(ctx context.Context, vp *VantagePoint, domain string) VantageObservation {
	startTime := time.Now()

	obs := VantageObservation{
		VantageID:  vp.ID,
		ObservedAt: time.Now(),
	}

	// Create query context with timeout
	queryCtx, cancel := context.WithTimeout(ctx, c.QueryTimeout)
	defer cancel()

	// Build request
	reqBody := map[string]string{"domain": domain}
	jsonBody, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(queryCtx, "POST", vp.Endpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		obs.Error = fmt.Sprintf("request creation failed: %v", err)
		return obs
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := c.client.Do(req)
	if err != nil {
		obs.Error = fmt.Sprintf("request failed: %v", err)
		obs.LatencyMs = time.Since(startTime).Milliseconds()
		return obs
	}
	defer resp.Body.Close()

	obs.LatencyMs = time.Since(startTime).Milliseconds()

	if resp.StatusCode != http.StatusOK {
		obs.Error = fmt.Sprintf("unexpected status: %d", resp.StatusCode)
		return obs
	}

	// Parse response
	body, _ := io.ReadAll(resp.Body)
	var vpResp struct {
		Fingerprint string    `json:"fingerprint"`
		Issuer      string    `json:"issuer"`
		Subject     string    `json:"subject"`
		NotBefore   time.Time `json:"not_before"`
		NotAfter    time.Time `json:"not_after"`
		Signature   []byte    `json:"signature"`
	}

	if err := json.Unmarshal(body, &vpResp); err != nil {
		obs.Error = fmt.Sprintf("response parse failed: %v", err)
		return obs
	}

	obs.Fingerprint = vpResp.Fingerprint
	obs.Issuer = vpResp.Issuer
	obs.Subject = vpResp.Subject
	obs.NotBefore = vpResp.NotBefore
	obs.NotAfter = vpResp.NotAfter
	obs.Signature = vpResp.Signature

	// Update vantage point health
	c.registry.UpdateHealth(vp.ID, true, obs.LatencyMs)

	return obs
}

// analyzeConsensus determines the consensus from collected observations.
func (c *ConsensusEngine) analyzeConsensus(response *DMTCResponse, clientFP string, threshold float64) {
	// Count fingerprints
	fpCount := make(map[string]int)
	validCount := 0

	for _, obs := range response.Observations {
		if obs.Error == "" && obs.Fingerprint != "" {
			fpCount[obs.Fingerprint]++
			validCount++
		}
	}

	if validCount == 0 {
		response.Verdict = VerdictError
		response.Message = "No valid observations received"
		return
	}

	// Find majority fingerprint
	var majorityFP string
	maxCount := 0
	for fp, count := range fpCount {
		if count > maxCount {
			maxCount = count
			majorityFP = fp
		}
	}

	response.MajorityFingerprint = majorityFP
	response.AgreementCount = maxCount
	response.AgreementRatio = float64(maxCount) / float64(validCount)

	// Check if consensus threshold is met
	if threshold == 0 {
		threshold = c.Threshold
	}
	response.ConsensusAchieved = response.AgreementRatio >= threshold

	// Check if majority matches client
	response.MatchesClient = majorityFP == clientFP

	// Determine verdict
	if !response.ConsensusAchieved {
		response.Verdict = VerdictNoConsensus
		response.Message = fmt.Sprintf("Consensus not achieved: only %.1f%% agreement (threshold: %.1f%%)",
			response.AgreementRatio*100, threshold*100)
	} else if response.MatchesClient {
		response.Verdict = VerdictSafe
		response.Message = fmt.Sprintf("Consensus achieved: %d/%d vantage points agree, certificate matches client observation",
			maxCount, validCount)
	} else if clientFP == "" {
		response.Verdict = VerdictSafe
		response.Message = fmt.Sprintf("Consensus achieved: %d/%d vantage points agree (no client fingerprint provided)",
			maxCount, validCount)
	} else {
		response.Verdict = VerdictMITMDetected
		response.Message = fmt.Sprintf("MITM DETECTED: Client fingerprint differs from %d/%d vantage point consensus",
			maxCount, validCount)
	}
}

// createThresholdSignature creates an aggregated signature from vantage point signatures.
func (c *ConsensusEngine) createThresholdSignature(observations []VantageObservation, majorityFP string) *ThresholdSignature {
	// Build message to sign (domain + fingerprint + timestamp)
	messageHash := sha256.Sum256([]byte(majorityFP))

	// Collect valid signatures
	signers := make([]SignerSignature, 0)
	signerIDs := make([]string, 0)

	for _, obs := range observations {
		if obs.Error == "" && obs.Fingerprint == majorityFP && len(obs.Signature) > 0 {
			signers = append(signers, SignerSignature{
				SignerID:  obs.VantageID,
				Signature: obs.Signature,
			})
			signerIDs = append(signerIDs, obs.VantageID)
		}
	}

	// Sort for deterministic output
	sort.Strings(signerIDs)

	return &ThresholdSignature{
		Threshold:    int(float64(len(observations)) * c.Threshold),
		TotalN:       len(observations),
		SignerIDs:    signerIDs,
		MessageHash:  messageHash[:],
		Signatures:   signers,
		AggregatedAt: time.Now(),
	}
}

// SignObservation signs an observation with this agent's private key.
func (c *ConsensusEngine) SignObservation(fingerprint string, domain string) []byte {
	message := fmt.Sprintf("%s:%s:%d", domain, fingerprint, time.Now().Unix())
	return ed25519.Sign(c.privateKey, []byte(message))
}

// VerifyObservationSignature verifies a vantage point's signature.
func VerifyObservationSignature(obs VantageObservation, publicKey ed25519.PublicKey) bool {
	message := fmt.Sprintf("%s:%s:%d", obs.VantageID, obs.Fingerprint, obs.ObservedAt.Unix())
	return ed25519.Verify(publicKey, []byte(message), obs.Signature)
}

// GetRequiredAgreement returns the minimum number of agreeing vantage points needed.
func (c *ConsensusEngine) GetRequiredAgreement(total int) int {
	required := int(float64(total)*c.Threshold) + 1
	if required > total {
		required = total
	}
	return required
}
