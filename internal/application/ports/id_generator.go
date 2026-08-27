package ports

import "github.com/vektcore/cortex/internal/domain/scan"

// IDGenerator hands out fresh scan IDs. Pulling this out of the domain
// keeps Scan construction deterministic and testable: production wires
// a UUID-backed implementation, tests wire a counter.
type IDGenerator interface {
	NewScanID() scan.ID
}
