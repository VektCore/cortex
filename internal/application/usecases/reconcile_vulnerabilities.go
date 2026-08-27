package usecases

import (
	"context"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/domain/vulnerability"
)

// ReconcileVulnerabilities folds a scan into the stored state, turning a list
// of findings into what a team can act on: what is new, what came back, what
// got fixed.
type ReconcileVulnerabilities struct {
	store  ports.VulnerabilityStore
	clock  shared.Clock
	logger ports.Logger
}

// ReconcileDeps is the constructor parameter struct.
type ReconcileDeps struct {
	Store  ports.VulnerabilityStore
	Clock  shared.Clock
	Logger ports.Logger
}

// NewReconcileVulnerabilities wires the use case.
func NewReconcileVulnerabilities(d ReconcileDeps) *ReconcileVulnerabilities {
	return &ReconcileVulnerabilities{store: d.Store, clock: d.Clock, logger: d.Logger}
}

// Execute reconciles and, unless asked not to, persists the result.
//
// Persisting is the caller's decision because a pull-request scan must not
// write the state of the main branch: it would record findings from a branch
// that may never merge, and mark as resolved everything the branch happens not
// to reach.
func (uc *ReconcileVulnerabilities) Execute(
	ctx context.Context, req dto.ReconcileRequest,
) mo.Result[dto.ReconcileResponse] {
	stored, err := uc.store.Load(ctx).Get()
	if err != nil {
		return shared.Err[dto.ReconcileResponse](err)
	}

	now := uc.clock.Now()
	result := vulnerability.Reconcile(stored, req.Findings, now)

	var persistErr error
	if req.Persist {
		if _, saveErr := uc.store.Save(ctx, result.All).Get(); saveErr != nil {
			// Losing the state costs the next scan its memory; it does not
			// invalidate this one.
			uc.logger.Warn("vulnerability state could not be saved",
				ports.F("error", saveErr.Error()))
			persistErr = saveErr
		}
	}

	uc.logger.Info("vulnerabilities reconciled",
		ports.F("known", len(stored)),
		ports.F("new", len(result.New)),
		ports.F("reopened", len(result.Reopened)),
		ports.F("resolved", len(result.Resolved)),
		ports.F("suppressed", len(result.Suppressed)),
		ports.F("persisted", req.Persist),
	)

	return shared.Ok(dto.ReconcileResponse{
		Result:       result,
		Known:        len(stored),
		PersistError: persistErr,
	})
}
