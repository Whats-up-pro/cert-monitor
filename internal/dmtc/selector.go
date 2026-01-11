// Package dmtc implements diversity-aware vantage point selection.
package dmtc

import (
	"errors"
	"math/rand"
	"sort"
	"time"
)

// Selector implements diversity-aware vantage point selection.
// Ensures anti-collusion by requiring geographic and network diversity.
type Selector struct {
	registry *Registry
	rng      *rand.Rand
}

// NewSelector creates a new diversity-aware selector.
func NewSelector(registry *Registry) *Selector {
	return &Selector{
		registry: registry,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// SelectionResult contains the selected vantage points and diversity metrics.
type SelectionResult struct {
	VantagePoints     []*VantagePoint
	DiversityAchieved DiversityMetrics
	DiversityMet      bool
	Message           string
}

// Select chooses vantage points meeting the diversity requirements.
// Uses a greedy algorithm prioritizing diversity over other factors.
func (s *Selector) Select(req DiversityRequirements) (*SelectionResult, error) {
	// Get all healthy vantage points
	candidates := s.registry.GetHealthy()
	if len(candidates) == 0 {
		return nil, errors.New("no healthy vantage points available")
	}

	// Shuffle candidates for randomness
	s.rng.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})

	// Sort by reputation (higher first) as secondary criteria
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].Reputation > candidates[j].Reputation
	})

	// Greedy selection with diversity constraints
	selected := make([]*VantagePoint, 0, req.TotalVantagePoints)
	asnCount := make(map[uint32]int)
	countryCount := make(map[string]int)
	providerSet := make(map[string]bool)

	// Phase 1: Ensure minimum distinct ASNs
	for _, vp := range candidates {
		if len(asnCount) < req.MinDistinctASNs {
			if _, seen := asnCount[vp.ASN]; !seen {
				selected = append(selected, vp)
				asnCount[vp.ASN]++
				countryCount[vp.Country]++
				providerSet[vp.Provider] = true
			}
		}
		if len(selected) >= req.TotalVantagePoints {
			break
		}
	}

	// Phase 2: Ensure minimum distinct countries
	for _, vp := range candidates {
		if s.isSelected(selected, vp) {
			continue
		}
		if len(countryCount) < req.MinDistinctCountries {
			if _, seen := countryCount[vp.Country]; !seen {
				if asnCount[vp.ASN] < req.MaxPerASN {
					selected = append(selected, vp)
					asnCount[vp.ASN]++
					countryCount[vp.Country]++
					providerSet[vp.Provider] = true
				}
			}
		}
		if len(selected) >= req.TotalVantagePoints {
			break
		}
	}

	// Phase 3: Ensure minimum distinct providers
	for _, vp := range candidates {
		if s.isSelected(selected, vp) {
			continue
		}
		if len(providerSet) < req.MinDistinctProviders {
			if !providerSet[vp.Provider] {
				if asnCount[vp.ASN] < req.MaxPerASN && countryCount[vp.Country] < req.MaxPerCountry {
					selected = append(selected, vp)
					asnCount[vp.ASN]++
					countryCount[vp.Country]++
					providerSet[vp.Provider] = true
				}
			}
		}
		if len(selected) >= req.TotalVantagePoints {
			break
		}
	}

	// Phase 4: Fill remaining slots respecting max constraints
	for _, vp := range candidates {
		if s.isSelected(selected, vp) {
			continue
		}
		if len(selected) >= req.TotalVantagePoints {
			break
		}
		if asnCount[vp.ASN] < req.MaxPerASN && countryCount[vp.Country] < req.MaxPerCountry {
			selected = append(selected, vp)
			asnCount[vp.ASN]++
			countryCount[vp.Country]++
			providerSet[vp.Provider] = true
		}
	}

	// Build result
	asns := make([]uint32, 0, len(asnCount))
	for asn := range asnCount {
		asns = append(asns, asn)
	}

	countries := make([]string, 0, len(countryCount))
	for country := range countryCount {
		countries = append(countries, country)
	}

	providers := make([]string, 0, len(providerSet))
	for provider := range providerSet {
		providers = append(providers, provider)
	}

	diversityMet := len(asnCount) >= req.MinDistinctASNs &&
		len(countryCount) >= req.MinDistinctCountries &&
		len(providerSet) >= req.MinDistinctProviders

	message := "Diversity requirements met"
	if !diversityMet {
		message = "Diversity requirements partially met due to limited vantage point availability"
	}

	return &SelectionResult{
		VantagePoints: selected,
		DiversityAchieved: DiversityMetrics{
			DistinctASNs:      len(asnCount),
			DistinctCountries: len(countryCount),
			DistinctProviders: len(providerSet),
			ASNList:           asns,
			CountryList:       countries,
			ProviderList:      providers,
		},
		DiversityMet: diversityMet,
		Message:      message,
	}, nil
}

// SelectRandom selects n random vantage points without diversity constraints.
// Used for fallback or testing.
func (s *Selector) SelectRandom(n int) []*VantagePoint {
	candidates := s.registry.GetHealthy()
	if len(candidates) <= n {
		return candidates
	}

	// Fisher-Yates shuffle
	s.rng.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})

	return candidates[:n]
}

// SelectByIDs selects specific vantage points by their IDs.
func (s *Selector) SelectByIDs(ids []string) []*VantagePoint {
	result := make([]*VantagePoint, 0, len(ids))
	for _, id := range ids {
		if vp, exists := s.registry.Get(id); exists && vp.IsHealthy {
			result = append(result, vp)
		}
	}
	return result
}

// isSelected checks if a vantage point is already in the selected list.
func (s *Selector) isSelected(selected []*VantagePoint, vp *VantagePoint) bool {
	for _, sel := range selected {
		if sel.ID == vp.ID {
			return true
		}
	}
	return false
}

// AnalyzeGeoTargeting checks if observations suggest a geo-targeted attack.
func AnalyzeGeoTargeting(observations []VantageObservation, registry *Registry) *GeoAttackDetection {
	if len(observations) < 2 {
		return &GeoAttackDetection{Suspected: false}
	}

	// Group observations by fingerprint
	byFingerprint := make(map[string][]VantageObservation)
	for _, obs := range observations {
		if obs.Error == "" {
			byFingerprint[obs.Fingerprint] = append(byFingerprint[obs.Fingerprint], obs)
		}
	}

	// If all fingerprints match, no geo-targeting suspected
	if len(byFingerprint) <= 1 {
		return &GeoAttackDetection{Suspected: false}
	}

	// Find majority fingerprint
	var majorityFP string
	maxCount := 0
	for fp, obs := range byFingerprint {
		if len(obs) > maxCount {
			maxCount = len(obs)
			majorityFP = fp
		}
	}

	// Identify affected regions/ASNs
	affectedRegions := make([]string, 0)
	affectedASNs := make([]uint32, 0)
	var affectedFP string

	for fp, obs := range byFingerprint {
		if fp != majorityFP {
			affectedFP = fp
			for _, o := range obs {
				if vp, exists := registry.Get(o.VantageID); exists {
					affectedRegions = append(affectedRegions, vp.Country)
					affectedASNs = append(affectedASNs, vp.ASN)
				}
			}
		}
	}

	// Calculate confidence based on distribution
	confidence := float64(len(observations)-maxCount) / float64(len(observations))

	return &GeoAttackDetection{
		Suspected:             true,
		AffectedRegions:       affectedRegions,
		AffectedASNs:          affectedASNs,
		AffectedFingerprint:   affectedFP,
		UnaffectedFingerprint: majorityFP,
		Confidence:            confidence,
	}
}
