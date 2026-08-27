package gate

import "github.com/vektcore/cortex/internal/domain/finding"

// Verdict is the result of evaluating a Policy. It is a closed sum type
// (Pass | Fail) represented as a single value object.
//
// Pass    → no violations.
// Fail    → at least one Rule was triggered; carries the list of
//
//	violations and a few sample findings per violation for
//	human-readable reporting.
type Verdict struct {
	passed     bool
	violations []Violation
}

// Pass constructs a passing Verdict.
func Pass() Verdict { return Verdict{passed: true} }

// Fail constructs a failing Verdict with the given violations.
func Fail(v []Violation) Verdict {
	return Verdict{passed: false, violations: append([]Violation(nil), v...)}
}

// Passed reports whether the gate passed.
func (v Verdict) Passed() bool { return v.passed }

// Failed is the inverse of Passed, provided for readability.
func (v Verdict) Failed() bool { return !v.passed }

// Violations returns a defensive copy of the violations list.
// Empty for a passing Verdict.
func (v Verdict) Violations() []Violation {
	return append([]Violation(nil), v.violations...)
}

// Violation describes one triggered rule.
type Violation struct {
	rule    Rule
	count   int
	samples []finding.Fingerprint
}

// NewViolation constructs a Violation.
func NewViolation(rule Rule, count int, samples []finding.Fingerprint) Violation {
	return Violation{
		rule:    rule,
		count:   count,
		samples: append([]finding.Fingerprint(nil), samples...),
	}
}

func (v Violation) Rule() Rule { return v.rule }
func (v Violation) Count() int { return v.count }
func (v Violation) Samples() []finding.Fingerprint {
	return append([]finding.Fingerprint(nil), v.samples...)
}
