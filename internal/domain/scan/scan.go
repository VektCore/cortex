package scan

import (
	"time"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// Scan is the aggregate root for one execution of the Cortex engine
// against a given revision. It owns the lifecycle status, the timestamps,
// and the (referential) list of findings produced.
//
// Findings are held by Fingerprint, not by value — keeping the Scan
// aggregate lean and avoiding accidental coupling to Finding internals.
//
// All transition methods return a NEW Scan; the receiver is never mutated.
type Scan struct {
	id        ID
	revision  Revision
	status    Status
	startedAt time.Time
	endedAt   time.Time
	failure   string
	findings  []finding.Fingerprint
	events    []DomainEvent
}

// New constructs a Scan in StatusQueued and records a Queued event.
func New(id ID, revision Revision) Scan {
	return Scan{
		id:       id,
		revision: revision,
		status:   StatusQueued,
		events:   []DomainEvent{Queued{ID: id, Revision: revision}},
	}
}

// Start transitions Queued → Running. Invalid otherwise.
func (s Scan) Start(now time.Time) mo.Result[Scan] {
	if s.status != StatusQueued {
		return shared.Err[Scan](shared.NewDomainError(
			"SCAN_BAD_TRANSITION",
			"cannot Start from "+s.status.String(),
		))
	}
	return shared.Ok(s.with(func(n *Scan) {
		n.status = StatusRunning
		n.startedAt = now
		n.append(Started{ID: s.id, At: now})
	}))
}

// Complete transitions Running → Completed and snapshots the findings'
// fingerprints. Invalid otherwise.
func (s Scan) Complete(now time.Time, findings []finding.Fingerprint) mo.Result[Scan] {
	if s.status != StatusRunning {
		return shared.Err[Scan](shared.NewDomainError(
			"SCAN_BAD_TRANSITION",
			"cannot Complete from "+s.status.String(),
		))
	}
	return shared.Ok(s.with(func(n *Scan) {
		n.status = StatusCompleted
		n.endedAt = now
		n.findings = append([]finding.Fingerprint(nil), findings...)
		n.append(Completed{ID: s.id, At: now, FindingsCount: len(findings)})
	}))
}

// Fail transitions any non-terminal status → Failed. Invalid from a
// terminal state.
func (s Scan) Fail(now time.Time, reason string) mo.Result[Scan] {
	if s.status.IsTerminal() {
		return shared.Err[Scan](shared.NewDomainError(
			"SCAN_BAD_TRANSITION",
			"cannot Fail from terminal status "+s.status.String(),
		))
	}
	return shared.Ok(s.with(func(n *Scan) {
		n.status = StatusFailed
		n.endedAt = now
		n.failure = reason
		n.append(Failed{ID: s.id, At: now, Reason: reason})
	}))
}

// with applies a mutation to a deep-enough copy of s and returns it.
// This is the only place we "mutate"; every public method goes through
// it so immutability is centrally enforced.
func (s Scan) with(mutate func(*Scan)) Scan {
	clone := s
	clone.events = append([]DomainEvent(nil), s.events...)
	clone.findings = append([]finding.Fingerprint(nil), s.findings...)
	mutate(&clone)
	return clone
}

func (s *Scan) append(e DomainEvent) { s.events = append(s.events, e) }

// Accessors.

func (s Scan) ID() ID               { return s.id }
func (s Scan) Revision() Revision   { return s.revision }
func (s Scan) Status() Status       { return s.status }
func (s Scan) StartedAt() time.Time { return s.startedAt }
func (s Scan) EndedAt() time.Time   { return s.endedAt }
func (s Scan) Failure() string      { return s.failure }
func (s Scan) Findings() []finding.Fingerprint {
	return append([]finding.Fingerprint(nil), s.findings...)
}
func (s Scan) Events() []DomainEvent { return append([]DomainEvent(nil), s.events...) }

// Duration returns the elapsed time if both timestamps are set.
func (s Scan) Duration() time.Duration {
	if s.startedAt.IsZero() || s.endedAt.IsZero() {
		return 0
	}
	return s.endedAt.Sub(s.startedAt)
}
