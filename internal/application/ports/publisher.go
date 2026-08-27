package ports

import (
	"context"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/scan"
)

// PublishRequest is what every Publisher receives.
//
// SARIF holds the merged, deduplicated document. Findings carries the
// same data in domain form for publishers that prefer it.
type PublishRequest struct {
	ScanID   scan.ID
	Revision scan.Revision
	Findings []finding.Finding
	SARIF    []byte
	Metadata map[string]string
}

// PublishReceipt is the acknowledgement returned by a Publisher.
type PublishReceipt struct {
	Publisher string
	Reference string // remote ID, URL, etc. — opaque
}

// Publisher ships scan results to an external system. Implementations
// are responsible for retries, backoff, and circuit breaking — the
// application layer never retries on their behalf.
type Publisher interface {
	Name() string
	Publish(ctx context.Context, req PublishRequest) mo.Result[PublishReceipt]
}
