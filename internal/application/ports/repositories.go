package ports

import (
	"context"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/scan"
)

// FindingRepository stores findings keyed by scan ID. The MVP backs
// this with the filesystem; richer backends can replace it without
// touching the application layer.
type FindingRepository interface {
	SaveAll(ctx context.Context, scanID scan.ID, findings []finding.Finding) error
	Load(ctx context.Context, scanID scan.ID) mo.Result[[]finding.Finding]
}

// ScanRepository persists Scan aggregates.
type ScanRepository interface {
	Save(ctx context.Context, s scan.Scan) error
	Load(ctx context.Context, id scan.ID) mo.Result[scan.Scan]
}

// BaselineRepository stores reference SARIF snapshots that the gate
// compares against for differential evaluation.
type BaselineRepository interface {
	Load(ctx context.Context, ref string) mo.Result[[]finding.Finding]
	Save(ctx context.Context, ref string, findings []finding.Finding) error
}
