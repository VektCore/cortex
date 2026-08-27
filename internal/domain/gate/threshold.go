package gate

// Operator is one of the comparison operators usable in a Threshold.
type Operator int

const (
	OpGreater Operator = iota
	OpGreaterEqual
	OpEqual
	OpLess
	OpLessEqual
)

// String returns the canonical symbol for the operator.
func (o Operator) String() string {
	switch o {
	case OpGreater:
		return ">"
	case OpGreaterEqual:
		return ">="
	case OpEqual:
		return "="
	case OpLess:
		return "<"
	case OpLessEqual:
		return "<="
	default:
		return "?"
	}
}

// Threshold is a count predicate used by gate rules.
//
//	"fail if count >= 1"  → Threshold{OpGreaterEqual, 1}
//	"fail if count > 5"   → Threshold{OpGreater, 5}
type Threshold struct {
	op    Operator
	value int
}

// NewThreshold constructs a Threshold. Value is clamped to ≥ 0.
func NewThreshold(op Operator, value int) Threshold {
	if value < 0 {
		value = 0
	}
	return Threshold{op: op, value: value}
}

// Op returns the operator.
func (t Threshold) Op() Operator { return t.op }

// Value returns the comparison target.
func (t Threshold) Value() int { return t.value }

// Triggers reports whether the given count satisfies the threshold.
func (t Threshold) Triggers(count int) bool {
	switch t.op {
	case OpGreater:
		return count > t.value
	case OpGreaterEqual:
		return count >= t.value
	case OpEqual:
		return count == t.value
	case OpLess:
		return count < t.value
	case OpLessEqual:
		return count <= t.value
	default:
		return false
	}
}
