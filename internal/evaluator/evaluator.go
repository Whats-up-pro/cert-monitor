// File: internal/evaluator/evaluator.go
package evaluator

import (
	"fmt"
	"time"
)

// AlertInfo holds the result of an evaluation.
type AlertInfo struct {
	ShouldAlert bool  // True if an alert is needed
	DaysLeft    int   // Number of days remaining
	Message     string // A descriptive message
}

// Evaluate checks a single domain's certificate expiry against the configured thresholds.
func Evaluate(domain string, expiryDate time.Time, thresholds []int) AlertInfo {
	// Calculate the number of days left until expiry.
	// We use time.Now() to get the current time.
	now := time.Now()
	durationLeft := expiryDate.Sub(now)
	daysLeft := int(durationLeft.Hours() / 24)

	// Check if the certificate has already expired.
	if daysLeft < 0 {
		return AlertInfo{
			ShouldAlert: true,
			DaysLeft:    daysLeft,
			Message:     fmt.Sprintf("CRITICAL: Certificate for %s has already expired!", domain),
		}
	}

	// Loop through the thresholds to see if an alert is triggered.
	for _, threshold := range thresholds {
		if daysLeft <= threshold {
			return AlertInfo{
				ShouldAlert: true,
				DaysLeft:    daysLeft,
				Message:     fmt.Sprintf("ALERT: Certificate for %s will expire in %d days (on %s).", domain, daysLeft, expiryDate.Format("2006-01-02")),
			}
		}
	}

	// If no threshold was met, no alert is needed.
	return AlertInfo{
		ShouldAlert: false,
		DaysLeft:    daysLeft,
		Message:     fmt.Sprintf("OK: Certificate for %s is valid for %d more days.", domain, daysLeft),
	}
}