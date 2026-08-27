package gate

import "github.com/vektcore/cortex/internal/domain/finding"

// Rule binds a Criteria (what counts) to a Threshold (when to fail).
// A Rule is itself a value object — immutable, comparable by value.
type Rule struct {
	name      string
	criteria  Criteria
	threshold Threshold
}

// NewRule constructs a Rule. Name is a human-readable label, surfaced in
// failure messages.
func NewRule(name string, c Criteria, t Threshold) Rule {
	return Rule{name: name, criteria: c, threshold: t}
}

func (r Rule) Name() string         { return r.name }
func (r Rule) Criteria() Criteria   { return r.criteria }
func (r Rule) Threshold() Threshold { return r.threshold }

// Matches is a convenience pass-through to Criteria.Matches.
func (r Rule) Matches(f finding.Finding) bool { return r.criteria.Matches(f) }

// Triggers is a convenience pass-through to Threshold.Triggers.
func (r Rule) Triggers(count int) bool { return r.threshold.Triggers(count) }
