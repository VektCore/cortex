package gate

import "github.com/vektcore/cortex/internal/domain/finding"

// MaxSamplesPerViolation caps the number of finding fingerprints
// attached to each Violation for reporting. Three is enough to be
// useful in a PR comment without flooding it.
const MaxSamplesPerViolation = 3

// Evaluate is the single domain service of this package: a pure function
// that turns (Policy, []Finding) into a Verdict.
//
// Rules are evaluated independently in their declared order. A rule
// triggers when the number of findings it Matches satisfies its
// Threshold. The Verdict aggregates every triggered rule as a Violation.
func Evaluate(policy Policy, findings []finding.Finding) Verdict {
	if policy.IsEmpty() {
		return Pass()
	}

	var violations []Violation
	for _, rule := range policy.Rules() {
		matches := matchesFor(rule, findings)
		if !rule.Triggers(len(matches)) {
			continue
		}
		violations = append(violations, NewViolation(
			rule,
			len(matches),
			sampleFingerprints(matches, MaxSamplesPerViolation),
		))
	}

	if len(violations) == 0 {
		return Pass()
	}
	return Fail(violations)
}

func matchesFor(rule Rule, findings []finding.Finding) []finding.Finding {
	matches := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		if rule.Matches(f) {
			matches = append(matches, f)
		}
	}
	return matches
}

func sampleFingerprints(findings []finding.Finding, limit int) []finding.Fingerprint {
	n := len(findings)
	if n > limit {
		n = limit
	}
	out := make([]finding.Fingerprint, n)
	for i := 0; i < n; i++ {
		out[i] = findings[i].Fingerprint()
	}
	return out
}
