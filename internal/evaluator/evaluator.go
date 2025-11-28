// File: internal/evaluator/evaluator.go
package evaluator

import (
	"cert-monitor/internal/checker"
	"fmt"
	"time"
)

// AlertInfo holds the result of an evaluation.
type AlertInfo struct {
	ShouldAlert bool   // True if an alert is needed
	DaysLeft    int    // Number of days remaining
	Message     string // A descriptive message
}

// Evaluate checks a single domain's certificate expiry against the configured thresholds.
func Evaluate(domain string, CertInfo checker.CertInfo, thresholds []int) AlertInfo {
	// Calculate the number of days left until expiry.
	// We use time.Now() to get the current time.
	now := time.Now()
	durationLeft := CertInfo.ExpiryDate.Sub(now)
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
				Message: fmt.Sprintf("ALERT: Certificate for %s (issued by %s) will expire in %d days (on %s).",
					domain, CertInfo.Issuer, daysLeft, CertInfo.ExpiryDate.Format("2006-01-02")),
			}
		}
	}

	// If no threshold was met, no alert is needed.
	return AlertInfo{
		ShouldAlert: false,
		DaysLeft:    daysLeft,
		Message: fmt.Sprintf("OK: Certificate for %s (issued by %s) is valid for %d more days.",
			domain, CertInfo.Issuer, daysLeft),
	}
}
