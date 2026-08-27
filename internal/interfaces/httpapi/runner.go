package httpapi

import (
	"context"
	"fmt"
	"time"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/application/usecases"
	"github.com/vektcore/cortex/internal/bootstrap"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/gate"
	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/infrastructure/config"
	gitinfra "github.com/vektcore/cortex/internal/infrastructure/git"
)

// Runner executes queued analyses: clone, scan, aggregate, gate, reconcile.
//
// It is deliberately a small pool rather than a job framework. Each analysis
// clones a repository and runs several scanners, so the useful concurrency is
// low and the failure modes worth handling are "the clone failed" and "a
// scanner is missing" — both of which the engine already reports.
type Runner struct {
	cfg    *config.Config
	store  *Store
	logger ports.Logger
	queue  chan string
	done   chan struct{}
}

// NewRunner starts `workers` goroutines draining the queue.
func NewRunner(cfg *config.Config, store *Store, logger ports.Logger, workers int) *Runner {
	if workers < 1 {
		workers = 1
	}
	r := &Runner{
		cfg:    cfg,
		store:  store,
		logger: logger,
		// Bounded: a full queue rejects new work with 503 instead of letting
		// the box accept thousands of clones it will never get to.
		queue: make(chan string, 256),
		done:  make(chan struct{}),
	}
	for i := 0; i < workers; i++ {
		go r.work()
	}
	return r
}

// Enqueue schedules an analysis by id. It reports false when the queue is full.
func (r *Runner) Enqueue(id string) bool {
	select {
	case r.queue <- id:
		return true
	default:
		return false
	}
}

// Stop stops accepting work. In-flight analyses finish.
func (r *Runner) Stop() { close(r.done) }

func (r *Runner) work() {
	for {
		select {
		case <-r.done:
			return
		case id := <-r.queue:
			r.run(id)
		}
	}
}

// run executes one analysis, recording every outcome — including failure — on
// the record the client polls.
func (r *Runner) run(id string) {
	analysis, found, err := r.store.LoadAnalysis(id)
	if err != nil || !found {
		r.logger.Error("analysis vanished from the store", ports.F("id", id))
		return
	}

	started := time.Now().UTC()
	analysis.Status = StatusRunning
	analysis.StartedAt = &started
	r.persist(analysis)

	r.logger.Info("analysis started",
		ports.F("id", id),
		ports.F("project", analysis.Project),
		ports.F("repository", gitinfra.Redact(analysis.Repository)))

	// A generous ceiling: cloning plus several scanners over a large monorepo
	// is minutes, but an analysis must never hang a worker forever.
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	if execErr := r.execute(ctx, &analysis); execErr != nil {
		analysis.Status = StatusFailed
		analysis.Error = execErr.Error()
	} else {
		analysis.Status = StatusCompleted
	}

	finished := time.Now().UTC()
	analysis.FinishedAt = &finished
	r.persist(analysis)

	r.logger.Info("analysis finished",
		ports.F("id", id),
		ports.F("status", analysis.Status),
		ports.F("findings", fmt.Sprint(analysis.Findings)),
		ports.F("new", fmt.Sprint(analysis.NewFindings)),
		ports.F("gate", analysis.Gate))
}

// execute is the analysis proper. It mutates the record with the results.
func (r *Runner) execute(ctx context.Context, analysis *Analysis) error {
	dir, cleanup, err := gitinfra.Clone(ctx, gitinfra.CloneSpec{
		URL: analysis.Repository,
		Ref: analysis.Ref,
	})
	if err != nil {
		return fmt.Errorf("clone: %w", err)
	}
	defer cleanup()

	codec := bootstrap.Codec()

	scanResp, scanErr := bootstrap.ExecuteScan(r.cfg, codec, r.logger).
		Execute(ctx, dto.ExecuteScanRequest{
			TargetPath:   dir,
			Settings:     r.cfg.ScannerSettings(),
			Exclude:      r.cfg.ExcludePatterns(),
			Escalations:  r.escalations(),
			Reachability: r.cfg.ReachabilitySettings(),
		}).Get()
	if scanErr != nil {
		return fmt.Errorf("scan: %w", scanErr)
	}

	analysis.ScannerErrors = namedErrors(scanResp.Errors)
	analysis.ScannersRan = len(scanResp.PerScanner)

	agg := usecases.NewAggregateFindings().Execute(dto.AggregateFindingsRequest{
		Inputs:       [][]finding.Finding{scanResp.Findings},
		CrossScanner: r.cfg.CrossScannerDedup(),
	})
	analysis.Findings = len(agg.Findings)
	analysis.BySeverity = countBySeverity(agg.Findings)

	if writeErr := r.writeSARIF(codec, analysis, scanResp, agg.Findings); writeErr != nil {
		return writeErr
	}

	policy, policyErr := r.cfg.BuildPolicy()
	if policyErr != nil {
		return fmt.Errorf("gate policy: %w", policyErr)
	}
	verdict := usecases.NewApplyQualityGate().Execute(dto.ApplyQualityGateRequest{
		Findings: agg.Findings,
		Policy:   policy,
		Baseline: shared.None[[]finding.Finding](),
	}).Verdict
	analysis.Gate = gateLabel(verdict)

	return r.reconcile(ctx, analysis, agg.Findings)
}

// reconcile folds the findings into the project's own history, which is what
// turns a repeated scan into "what changed since last time".
func (r *Runner) reconcile(
	ctx context.Context, analysis *Analysis, findings []finding.Finding,
) error {
	store := bootstrap.StoreAt(r.store.ProjectStatePath(analysis.Project))

	resp, err := bootstrap.ReconcileWith(store, r.logger).
		Execute(ctx, dto.ReconcileRequest{Findings: findings, Persist: true}).Get()
	if err != nil {
		return fmt.Errorf("reconcile: %w", err)
	}
	if resp.PersistError != nil {
		// The results stand; the history did not save. Say so rather than
		// reporting a clean run.
		analysis.Error = fmt.Sprintf("state not saved: %v", resp.PersistError)
	}

	analysis.NewFindings = len(resp.Result.New)
	analysis.Reopened = len(resp.Result.Reopened)
	analysis.Resolved = len(resp.Result.Resolved)
	analysis.KnownBefore = resp.Known
	return nil
}

func (r *Runner) writeSARIF(
	codec ports.SarifCodec,
	analysis *Analysis,
	scanResp dto.ExecuteScanResponse,
	deduped []finding.Finding,
) error {
	doc, err := codec.Write(deduped, ports.SarifMetadata{
		Tool:     "cortex",
		Revision: scanResp.Scan.Revision(),
	}).Get()
	if err != nil {
		return fmt.Errorf("write SARIF: %w", err)
	}
	if writeErr := r.store.WriteBlob(r.store.SarifPath(analysis.ID), doc); writeErr != nil {
		return fmt.Errorf("store SARIF: %w", writeErr)
	}
	return nil
}

func (r *Runner) escalations() map[finding.CWE]shared.Severity {
	escalations, err := r.cfg.SeverityEscalations()
	if err != nil {
		r.logger.Warn("severity escalations ignored", ports.F("error", err.Error()))
		return nil
	}
	return escalations
}

func (r *Runner) persist(a Analysis) {
	if err := r.store.SaveAnalysis(a); err != nil {
		r.logger.Error("could not persist analysis",
			ports.F("id", a.ID), ports.F("error", err.Error()))
	}
}

func gateLabel(verdict gate.Verdict) string {
	if verdict.Failed() {
		return "failed"
	}
	return "passed"
}

func namedErrors(errs map[finding.ScannerName]error) map[string]string {
	if len(errs) == 0 {
		return nil
	}
	out := make(map[string]string, len(errs))
	for name, err := range errs {
		out[string(name)] = err.Error()
	}
	return out
}

func countBySeverity(findings []finding.Finding) map[string]int {
	out := make(map[string]int, 5)
	for _, f := range findings {
		out[f.Severity().String()]++
	}
	return out
}
