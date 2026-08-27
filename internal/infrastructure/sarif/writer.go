package sarif

import (
	"bytes"
	"fmt"

	gosarif "github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

const cortexInfoURI = "https://github.com/vektcore/cortex"

// Result properties Cortex adds to its own documents so a write→parse round
// trip is lossless.
const (
	ScannerProperty      = "cortex/scanner"
	FingerprintProperty  = "cortex/fingerprint"
	SymbolProperty       = "cortex/symbol"
	ReachabilityProperty = "cortex/reachability"
)

// writeBytes serializes domain Findings as a SARIF 2.1.0 document.
func writeBytes(findings []finding.Finding, meta ports.SarifMetadata) ([]byte, error) {
	report, err := gosarif.New(gosarif.Version210)
	if err != nil {
		return nil, fmt.Errorf("sarif writer: create report: %w", err)
	}

	run := gosarif.NewRunWithInformationURI(meta.Tool, cortexInfoURI)
	version := meta.Version
	run.Tool.Driver.Version = &version

	rulesSeen := make(map[string]bool)
	for i := range findings {
		f := findings[i]
		ruleID := f.RuleID().String()

		if !rulesSeen[ruleID] {
			rulesSeen[ruleID] = true
			rule := gosarif.NewRule(ruleID)
			// The rule-level score is what GitHub Code Scanning reads; the
			// result-level one above is what Cortex reads back.
			props := gosarif.Properties{
				"security-severity": securitySeverityScore(f.Severity()),
			}
			if cwe, ok := f.CWE().Get(); ok {
				props["tags"] = []string{cwe.String()}
			}
			rule.Properties = props
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
		}

		result := gosarif.NewRuleResult(ruleID).
			WithLevel(severityToSARIFLevel(f.Severity())).
			WithMessage(gosarif.NewMessage().WithText(f.Message().String()))

		// Which tool found it, and its identity. Without these, a document
		// Cortex wrote and read back would attribute every finding to "cortex"
		// and re-fingerprint it — breaking provenance in reports and baseline
		// comparison, since the snippet is not serialized.
		result.Properties = gosarif.Properties{
			ScannerProperty:     f.Source().String(),
			FingerprintProperty: f.Fingerprint().String(),
			// Per result, not only per rule: two findings of the same rule can
			// legitimately differ in severity — one sits in dead code, the
			// other on a live path — and a rule-level score cannot say so.
			"security-severity": securitySeverityScore(f.Severity()),
		}
		if f.SymbolName() != "" {
			result.Properties[SymbolProperty] = f.SymbolName()
		}
		if f.Reachability() != finding.ReachabilityUnknown {
			result.Properties[ReachabilityProperty] = f.Reachability().String()
		}

		loc := f.Location()
		region := gosarif.NewRegion().
			WithStartLine(loc.StartLine()).
			WithEndLine(loc.EndLine()).
			WithStartColumn(loc.StartCol()).
			WithEndColumn(loc.EndCol())

		physLoc := gosarif.NewPhysicalLocation().
			WithArtifactLocation(gosarif.NewArtifactLocation().WithUri(loc.File())).
			WithRegion(region)

		result.AddLocation(gosarif.NewLocation().WithPhysicalLocation(physLoc))
		run.AddResult(result)
	}

	report.AddRun(run)

	var buf bytes.Buffer
	if err := report.Write(&buf); err != nil {
		return nil, fmt.Errorf("sarif writer: encode: %w", err)
	}
	return buf.Bytes(), nil
}

// securitySeverityScore maps a Severity onto the CVSS band the parser reads
// back, keeping write→parse lossless.
func securitySeverityScore(s shared.Severity) string {
	switch s {
	case shared.SeverityCritical:
		return "9.5"
	case shared.SeverityHigh:
		return "7.5"
	case shared.SeverityMedium:
		return "5.0"
	case shared.SeverityLow:
		return "2.0"
	case shared.SeverityInfo:
		return "0.0"
	default:
		return "0.0"
	}
}

func severityToSARIFLevel(s shared.Severity) string {
	switch s {
	case shared.SeverityCritical, shared.SeverityHigh:
		return "error"
	case shared.SeverityMedium:
		return "warning"
	case shared.SeverityLow:
		return "note"
	case shared.SeverityInfo:
		return "none"
	default:
		return "none"
	}
}
