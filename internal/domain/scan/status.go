package scan

// Status represents the lifecycle state of a Scan.
//
// Transitions:
//
//	Queued ──Start──▶ Running ──Complete──▶ Completed (terminal)
//	   │                  │
//	   └──Fail──▶ Failed (terminal)
//	                      │
//	                      └──Fail──▶ Failed (terminal)
type Status int

const (
	StatusQueued Status = iota
	StatusRunning
	StatusCompleted
	StatusFailed
)

// String implements fmt.Stringer.
func (s Status) String() string {
	switch s {
	case StatusQueued:
		return "queued"
	case StatusRunning:
		return "running"
	case StatusCompleted:
		return "completed"
	case StatusFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// IsTerminal reports whether the scan has reached an end state.
func (s Status) IsTerminal() bool {
	return s == StatusCompleted || s == StatusFailed
}
