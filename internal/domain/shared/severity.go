package shared

import "strings"

// Severity is an ordered enum: Info < Low < Medium < High < Critical.
// Comparisons rely on this order, so the integer values are part of the
// public contract.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String returns the canonical lowercase representation.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
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

// AtLeast reports whether s ≥ other in the severity order.
func (s Severity) AtLeast(other Severity) bool { return s >= other }

// IsValid reports whether s is one of the named constants.
func (s Severity) IsValid() bool {
	return s >= SeverityInfo && s <= SeverityCritical
}

// ParseSeverity normalizes scanner vocabularies (warning, error, blocker,
// note…) into the canonical Severity enum. Unknown inputs map to Info.
//
// This is the single normalization point — every scanner adapter must
// route severities through here.
func ParseSeverity(raw string) Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "info", "note", "informational", "none":
		return SeverityInfo
	case "low", "minor", "advice":
		return SeverityLow
	case "medium", "warning", "moderate", "warn":
		return SeverityMedium
	case "high", "error", "important":
		return SeverityHigh
	case "critical", "blocker", "fatal":
		return SeverityCritical
	default:
		return SeverityInfo
	}
}
