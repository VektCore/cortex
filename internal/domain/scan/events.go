package scan

import "time"

// DomainEvent is implemented by every event recorded by the Scan aggregate.
type DomainEvent interface {
	EventName() string
}

// Queued is recorded the moment a Scan is constructed.
type Queued struct {
	ID       ID
	Revision Revision
}

func (Queued) EventName() string { return "scan.queued" }

// Started is recorded on transition Queued → Running.
type Started struct {
	ID ID
	At time.Time
}

func (Started) EventName() string { return "scan.started" }

// Completed is recorded on transition Running → Completed.
type Completed struct {
	ID            ID
	At            time.Time
	FindingsCount int
}

func (Completed) EventName() string { return "scan.completed" }

// Failed is recorded on any → Failed transition.
type Failed struct {
	ID     ID
	At     time.Time
	Reason string
}

func (Failed) EventName() string { return "scan.failed" }
