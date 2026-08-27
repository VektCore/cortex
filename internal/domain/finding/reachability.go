package finding

import "strings"

// Reachability says whether the code holding the finding can actually be
// reached from somewhere in the project.
//
// It exists because the fastest way to lose a team's attention is a queue full
// of findings in code nobody calls. A weakness in dead code is real but not
// urgent, and saying so explicitly is more honest than either hiding it or
// ranking it alongside a live SQL injection.
type Reachability int

const (
	// ReachabilityUnknown is the default: no analysis ran, or it could not
	// tell. Never treated as a signal.
	ReachabilityUnknown Reachability = iota
	// ReachabilityReachable means the enclosing symbol is referenced elsewhere.
	ReachabilityReachable
	// ReachabilityUnreachable means nothing in the project references the
	// enclosing symbol. Still a guess — frameworks call code by name, at
	// runtime — so it lowers priority rather than dismissing the finding.
	ReachabilityUnreachable
)

// String returns the canonical lowercase representation.
func (r Reachability) String() string {
	switch r {
	case ReachabilityReachable:
		return "reachable"
	case ReachabilityUnreachable:
		return "unreachable"
	case ReachabilityUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// ParseReachability reads a stored value, defaulting to unknown.
func ParseReachability(raw string) Reachability {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "reachable":
		return ReachabilityReachable
	case "unreachable":
		return ReachabilityUnreachable
	default:
		return ReachabilityUnknown
	}
}
