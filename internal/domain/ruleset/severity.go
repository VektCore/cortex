package ruleset

import (
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// Severity policy.
//
// No scanner in the MVP set emits a CVSS score, and SARIF's own vocabulary
// stops at "error" — which normalizes to high. The consequence is that nothing
// is ever critical, so the default "fail on any critical" gate rule can never
// fire, not even on the SQL injection in the fixture. Severity therefore has to
// come partly from the weakness class, and that is a product decision: it lives
// in configuration, with the defaults below.

// DefaultEscalations raises severity for weakness classes that are critical
// whenever they are real: an attacker-controlled path straight to code or data
// execution. Deliberately narrow — everything doubtful stays where the scanner
// put it.
func DefaultEscalations() map[finding.CWE]shared.Severity {
	return map[finding.CWE]shared.Severity{
		"CWE-89":  shared.SeverityCritical, // SQL injection
		"CWE-78":  shared.SeverityCritical, // OS command injection
		"CWE-94":  shared.SeverityCritical, // code injection
		"CWE-95":  shared.SeverityCritical, // eval injection
		"CWE-502": shared.SeverityCritical, // insecure deserialization
		"CWE-611": shared.SeverityHigh,     // XXE
		"CWE-798": shared.SeverityHigh,     // hardcoded credentials
		"CWE-22":  shared.SeverityHigh,     // path traversal
		"CWE-79":  shared.SeverityHigh,     // XSS
		"CWE-918": shared.SeverityHigh,     // SSRF
	}
}

// EscalationFloor is the severity a finding must already have before the
// weakness class can raise it.
//
// Scanners emit plenty of low/info advisories — "you imported this module",
// "consider a timeout" — that share a CWE with a real exploit. Escalating those
// turns the gate into a false-positive machine, so the scanner's own judgement
// gates the escalation: it has to consider the finding at least a medium.
const EscalationFloor = shared.SeverityMedium

// Escalate raises the severity of findings whose CWE appears in the policy and
// that the scanner already rated at EscalationFloor or above.
//
// It only ever raises: a scanner reporting something as critical is trusted
// over the table, so a policy entry can never downgrade a finding.
func Escalate(
	findings []finding.Finding,
	policy map[finding.CWE]shared.Severity,
) []finding.Finding {
	if len(findings) == 0 || len(policy) == 0 {
		return findings
	}

	out := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		cwe, has := f.CWE().Get()
		if !has {
			out = append(out, f)
			continue
		}
		// A finding the reachability analysis put in dead code was deliberately
		// lowered. Escalating it would undo that decision — and would do so
		// invisibly every time a stored SARIF is read back.
		if f.Reachability() == finding.ReachabilityUnreachable {
			out = append(out, f)
			continue
		}
		if !f.Severity().AtLeast(EscalationFloor) {
			out = append(out, f)
			continue
		}
		target, mapped := policy[cwe]
		if !mapped || !target.AtLeast(f.Severity()) || target == f.Severity() {
			out = append(out, f)
			continue
		}
		out = append(out, f.WithSeverity(target))
	}
	return out
}
