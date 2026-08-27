package gate

// Policy is the aggregate root of the gate bounded context. It owns an
// ordered list of Rules. Evaluation visits rules in their declared order
// so that violation messages are stable.
type Policy struct {
	rules []Rule
}

// NewPolicy constructs a Policy. The rules slice is defensively copied.
func NewPolicy(rules []Rule) Policy {
	return Policy{rules: append([]Rule(nil), rules...)}
}

// Rules returns a copy of the policy's rules.
func (p Policy) Rules() []Rule { return append([]Rule(nil), p.rules...) }

// IsEmpty reports whether the policy has no rules — useful to detect a
// misconfiguration (an empty policy always passes).
func (p Policy) IsEmpty() bool { return len(p.rules) == 0 }
