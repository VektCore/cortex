package finding

import "github.com/vektcore/cortex/internal/domain/shared"

// DomainEvent is implemented by every event emitted from this package.
// The application layer can subscribe to events for telemetry, audit,
// or downstream side effects — but the domain itself never publishes
// them; it only records them.
type DomainEvent interface {
	EventName() string
}

// Detected is recorded when a new Finding enters the system.
type Detected struct {
	Fingerprint Fingerprint
	RuleID      RuleID
	Severity    shared.Severity
	Source      ScannerName
}

func (Detected) EventName() string { return "finding.detected" }

// Suppressed is recorded when a Finding is filtered by an
// allowlist rule before reaching the gate.
type Suppressed struct {
	Fingerprint Fingerprint
	Reason      string
}

func (Suppressed) EventName() string { return "finding.suppressed" }
