package ruleset

import (
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// ApplyReachability labels findings with the analysis result and, when demote
// is set, lowers the priority of the ones in code nothing calls.
//
// Demotion is one step and never below low. A weakness in dead code is still a
// weakness: today's unused helper is next sprint's endpoint, and the analysis
// is a heuristic that cannot see reflection or framework dispatch. Lowering it
// to info would be the same as deleting it.
func ApplyReachability(
	findings []finding.Finding, unreachable map[string]bool, demote bool,
) []finding.Finding {
	if len(findings) == 0 || len(unreachable) == 0 {
		return findings
	}

	out := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		dead, decided := unreachable[f.SymbolName()]
		if !decided {
			out = append(out, f) // stays unknown
			continue
		}

		if !dead {
			out = append(out, f.WithReachability(finding.ReachabilityReachable))
			continue
		}

		labelled := f.WithReachability(finding.ReachabilityUnreachable)
		if demote {
			labelled = labelled.WithSeverity(demoteOnce(labelled.Severity()))
		}
		out = append(out, labelled)
	}
	return out
}

func demoteOnce(s shared.Severity) shared.Severity {
	switch s {
	case shared.SeverityCritical:
		return shared.SeverityHigh
	case shared.SeverityHigh:
		return shared.SeverityMedium
	case shared.SeverityMedium:
		return shared.SeverityLow
	case shared.SeverityLow, shared.SeverityInfo:
		// Already at the bottom: a weakness in dead code is still a weakness.
		return s
	default:
		return s
	}
}
