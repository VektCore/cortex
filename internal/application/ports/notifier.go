package ports

import (
	"context"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/domain/gate"
	"github.com/vektcore/cortex/internal/domain/scan"
)

// NotificationEvent enumerates the moments that may trigger a Notifier.
type NotificationEvent int

const (
	NotifyGatePassed NotificationEvent = iota
	NotifyGateFailed
	NotifyScanCompleted
	NotifyScanFailed
)

// String returns a stable identifier used in config files.
func (e NotificationEvent) String() string {
	switch e {
	case NotifyGatePassed:
		return "gate_passed"
	case NotifyGateFailed:
		return "gate_failed"
	case NotifyScanCompleted:
		return "scan_completed"
	case NotifyScanFailed:
		return "scan_failed"
	default:
		return "unknown"
	}
}

// Notification is the payload delivered to a Notifier.
type Notification struct {
	Event   NotificationEvent
	ScanID  scan.ID
	Verdict mo.Option[gate.Verdict]
	Summary string
}

// Notifier interrupts a human (PR comment, Slack, console). Notifiers
// must not be load-bearing — a failed notification never fails the gate.
type Notifier interface {
	Name() string
	SupportedEvents() []NotificationEvent
	Notify(ctx context.Context, n Notification) error
}
