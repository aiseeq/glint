package core

import (
	"fmt"
	"strings"
)

// Severity represents the severity level of a violation
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String returns the string representation of severity
func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Label returns a formatted label for display
func (s Severity) Label() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// ParseSeverity converts a string to Severity
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low", "l":
		return SeverityLow, nil
	case "medium", "med", "m":
		return SeverityMedium, nil
	case "high", "h":
		return SeverityHigh, nil
	case "critical", "crit", "c":
		return SeverityCritical, nil
	default:
		return SeverityLow, fmt.Errorf("unknown severity: %q", s)
	}
}

// IsAtLeast returns true if this severity is at least as severe as other
func (s Severity) IsAtLeast(other Severity) bool {
	return s >= other
}
