// Package dmtc implements registry for decentralized vantage point discovery.
package dmtc

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

// Registry implements a lightweight DHT-like registry for vantage point discovery.
// Uses consistent hashing for distributed lookup.
type Registry struct {
	mu sync.RWMutex

	// All registered vantage points
	vantagePoints map[string]*VantagePoint

	// Index by ASN for diversity queries
	byASN map[uint32][]*VantagePoint

	// Index by country for diversity queries
	byCountry map[string][]*VantagePoint

	// Index by provider for diversity queries
	byProvider map[string][]*VantagePoint

	// Sorted node IDs for consistent hashing
	ring []string

	// Health check interval
	healthCheckInterval time.Duration

	// Registry entry TTL
	entryTTL time.Duration
}

// NewRegistry creates a new vantage point registry.
func NewRegistry() *Registry {
	return &Registry{
		vantagePoints:       make(map[string]*VantagePoint),
		byASN:               make(map[uint32][]*VantagePoint),
		byCountry:           make(map[string][]*VantagePoint),
		byProvider:          make(map[string][]*VantagePoint),
		ring:                make([]string, 0),
		healthCheckInterval: 30 * time.Second,
		entryTTL:            24 * time.Hour,
	}
}

// Register adds a vantage point to the registry.
func (r *Registry) Register(vp *VantagePoint) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Set registration time
	vp.RegisteredAt = time.Now()
	vp.IsHealthy = true

	// Add to main map
	r.vantagePoints[vp.ID] = vp

	// Add to indices
	r.byASN[vp.ASN] = append(r.byASN[vp.ASN], vp)
	r.byCountry[vp.Country] = append(r.byCountry[vp.Country], vp)
	r.byProvider[vp.Provider] = append(r.byProvider[vp.Provider], vp)

	// Update consistent hash ring
	r.rebuildRing()

	return nil
}

// Unregister removes a vantage point from the registry.
func (r *Registry) Unregister(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	vp, exists := r.vantagePoints[id]
	if !exists {
		return
	}

	// Remove from indices
	asnSlice := r.byASN[vp.ASN]
	r.removeFromSlice(&asnSlice, vp)
	r.byASN[vp.ASN] = asnSlice

	countrySlice := r.byCountry[vp.Country]
	r.removeFromSlice(&countrySlice, vp)
	r.byCountry[vp.Country] = countrySlice

	providerSlice := r.byProvider[vp.Provider]
	r.removeFromSlice(&providerSlice, vp)
	r.byProvider[vp.Provider] = providerSlice

	// Remove from main map
	delete(r.vantagePoints, id)

	// Rebuild ring
	r.rebuildRing()
}

// Get retrieves a vantage point by ID.
func (r *Registry) Get(id string) (*VantagePoint, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	vp, exists := r.vantagePoints[id]
	return vp, exists
}

// GetAll returns all registered vantage points.
func (r *Registry) GetAll() []*VantagePoint {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*VantagePoint, 0, len(r.vantagePoints))
	for _, vp := range r.vantagePoints {
		result = append(result, vp)
	}
	return result
}

// GetHealthy returns all healthy vantage points.
func (r *Registry) GetHealthy() []*VantagePoint {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*VantagePoint, 0)
	for _, vp := range r.vantagePoints {
		if vp.IsHealthy {
			result = append(result, vp)
		}
	}
	return result
}

// GetByASN returns vantage points in a specific ASN.
func (r *Registry) GetByASN(asn uint32) []*VantagePoint {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.byASN[asn]
}

// GetByCountry returns vantage points in a specific country.
func (r *Registry) GetByCountry(country string) []*VantagePoint {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.byCountry[country]
}

// GetDiversityStats returns current diversity statistics.
func (r *Registry) GetDiversityStats() DiversityMetrics {
	r.mu.RLock()
	defer r.mu.RUnlock()

	asns := make([]uint32, 0, len(r.byASN))
	for asn := range r.byASN {
		asns = append(asns, asn)
	}

	countries := make([]string, 0, len(r.byCountry))
	for country := range r.byCountry {
		countries = append(countries, country)
	}

	providers := make([]string, 0, len(r.byProvider))
	for provider := range r.byProvider {
		providers = append(providers, provider)
	}

	return DiversityMetrics{
		DistinctASNs:      len(asns),
		DistinctCountries: len(countries),
		DistinctProviders: len(providers),
		ASNList:           asns,
		CountryList:       countries,
		ProviderList:      providers,
	}
}

// UpdateHealth updates the health status of a vantage point.
func (r *Registry) UpdateHealth(id string, healthy bool, latencyMs int64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if vp, exists := r.vantagePoints[id]; exists {
		vp.IsHealthy = healthy
		vp.LastHealthCheck = time.Now()
		// Exponential moving average for latency
		if vp.AvgLatencyMs == 0 {
			vp.AvgLatencyMs = latencyMs
		} else {
			vp.AvgLatencyMs = (vp.AvgLatencyMs*7 + latencyMs*3) / 10
		}
	}
}

// UpdateReputation updates the reputation score of a vantage point.
func (r *Registry) UpdateReputation(id string, delta float64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if vp, exists := r.vantagePoints[id]; exists {
		vp.Reputation += delta
		if vp.Reputation > 1.0 {
			vp.Reputation = 1.0
		}
		if vp.Reputation < 0.0 {
			vp.Reputation = 0.0
		}
	}
}

// Count returns the number of registered vantage points.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.vantagePoints)
}

// hashID creates a consistent hash for a vantage point ID.
func hashID(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:])
}

// rebuildRing rebuilds the consistent hash ring.
func (r *Registry) rebuildRing() {
	r.ring = make([]string, 0, len(r.vantagePoints))
	for id := range r.vantagePoints {
		r.ring = append(r.ring, id)
	}
	sort.Strings(r.ring)
}

// removeFromSlice removes a vantage point from a slice.
func (r *Registry) removeFromSlice(slice *[]*VantagePoint, vp *VantagePoint) {
	for i, v := range *slice {
		if v.ID == vp.ID {
			*slice = append((*slice)[:i], (*slice)[i+1:]...)
			return
		}
	}
}

// DefaultVantagePoints returns a list of default demo vantage points.
func DefaultVantagePoints() []*VantagePoint {
	return []*VantagePoint{
		{
			ID:         "vp-us-east-1",
			Endpoint:   "https://vp-us-east.trustguard.network/api/v2/observe",
			ASN:        14618,
			ASNOrg:     "Amazon.com, Inc.",
			Country:    "US",
			Provider:   "AWS",
			Region:     "us-east",
			Reputation: 1.0,
		},
		{
			ID:         "vp-eu-west-1",
			Endpoint:   "https://vp-eu-west.trustguard.network/api/v2/observe",
			ASN:        15169,
			ASNOrg:     "Google LLC",
			Country:    "DE",
			Provider:   "GCP",
			Region:     "eu-west",
			Reputation: 1.0,
		},
		{
			ID:         "vp-ap-sg-1",
			Endpoint:   "https://vp-ap-sg.trustguard.network/api/v2/observe",
			ASN:        13335,
			ASNOrg:     "Cloudflare, Inc.",
			Country:    "SG",
			Provider:   "Cloudflare",
			Region:     "ap-southeast",
			Reputation: 1.0,
		},
		{
			ID:         "vp-ap-jp-1",
			Endpoint:   "https://vp-ap-jp.trustguard.network/api/v2/observe",
			ASN:        2516,
			ASNOrg:     "KDDI Corporation",
			Country:    "JP",
			Provider:   "KDDI",
			Region:     "ap-northeast",
			Reputation: 1.0,
		},
		{
			ID:         "vp-sa-br-1",
			Endpoint:   "https://vp-sa-br.trustguard.network/api/v2/observe",
			ASN:        16509,
			ASNOrg:     "Amazon.com, Inc.",
			Country:    "BR",
			Provider:   "AWS",
			Region:     "sa-east",
			Reputation: 1.0,
		},
	}
}
