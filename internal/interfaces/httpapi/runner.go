package httpapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/application/usecases"
	"github.com/vektcore/cortex/internal/bootstrap"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/gate"
	"github.com/vektcore/cortex/internal/domain/scan"
	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/infrastructure/archive"
	"github.com/vektcore/cortex/internal/infrastructure/config"
	gitinfra "github.com/vektcore/cortex/internal/infrastructure/git"
	ghpublish "github.com/vektcore/cortex/internal/infrastructure/publishers/github_code_scanning"
	platformpublish "github.com/vektcore/cortex/internal/infrastructure/publishers/vektcore_platform"
)

const (
	// analysisTimeout caps one analysis: a clone plus several scanners.
	analysisTimeout = 45 * time.Minute
	// shutdownGrace is how long Stop waits for in-flight work.
	shutdownGrace = 30 * time.Second
)

// Runner executes queued analyses: obtain the source, scan, aggregate, gate,
// reconcile.
//
// It is deliberately a small pool rather than a job framework. Each analysis
// clones a repository and runs several scanners, so the useful concurrency is
// low and the failure modes worth handling are "the clone failed" and "a
// scanner is missing" — both of which the engine already reports.
type Runner struct {
	cfg *config.Config
	// store owns what stays on disk whatever the backend: the uploaded
	// archive and the directory it is expanded into.
	store *Store
	// records is where the analysis and its SARIF are kept — a file or a
	// database, decided by server.database.
	records analysisRecords
	logger  ports.Logger
	queue   chan string
	// ctx is cancelled on Stop, which aborts the clone and the scanners of an
	// in-flight analysis rather than leaving them orphaned.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewRunner starts `workers` goroutines draining the queue.
func NewRunner(
	cfg *config.Config, store *Store, records analysisRecords,
	logger ports.Logger, workers int,
) *Runner {
	if workers < 1 {
		workers = 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Runner{
		cfg:     cfg,
		store:   store,
		records: records,
		logger:  logger,
		// Bounded: a full queue rejects new work with 503 instead of letting
		// the box accept thousands of clones it will never get to.
		queue:  make(chan string, 256),
		ctx:    ctx,
		cancel: cancel,
	}
	r.wg.Add(workers)
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

// Stop cancels in-flight analyses and waits for the workers to return.
//
// Waiting matters twice over. On a redeploy, an analysis killed mid-flight
// would stay "running" in the store forever, with no worker left to finish it.
// And in tests, a worker still writing into a temp directory outlives the test
// that created it.
//
// The wait is bounded: a scanner wedged on a huge repository must not hold a
// shutdown open indefinitely.
func (r *Runner) Stop() {
	r.cancel()

	finished := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(finished)
	}()

	select {
	case <-finished:
	case <-time.After(shutdownGrace):
		r.logger.Warn("workers did not stop in time; abandoning them",
			ports.F("grace", shutdownGrace.String()))
	}
}

func (r *Runner) work() {
	defer r.wg.Done()
	for {
		select {
		case <-r.ctx.Done():
			return
		case id := <-r.queue:
			r.run(id)
		}
	}
}

// run executes one analysis, recording every outcome — including failure — on
// the record the client polls.
func (r *Runner) run(id string) {
	analysis, found, err := r.records.LoadAnalysis(context.Background(), id)
	if err != nil || !found {
		r.logger.Error("analysis vanished from the store", ports.F("id", id))
		return
	}

	// The archive holds the client's source. It is dropped on every exit path,
	// including a failed scan, so the data directory never becomes a copy of
	// every repository the service has seen.
	if analysis.Source == SourceUpload {
		defer r.removeArchive(id)
	}

	started := time.Now().UTC()
	analysis.Status = StatusRunning
	analysis.StartedAt = &started
	r.persist(analysis)

	r.logger.Info("analysis started",
		ports.F("id", id),
		ports.F("project", analysis.Project),
		ports.F("source", analysis.Source),
		ports.F("repository", gitinfra.Redact(analysis.Repository)))

	// A generous ceiling: cloning plus several scanners over a large monorepo
	// is minutes, but an analysis must never hang a worker forever. Derived
	// from the runner's context, so a shutdown aborts it too.
	ctx, cancel := context.WithTimeout(r.ctx, analysisTimeout)
	defer cancel()

	switch execErr := r.execute(ctx, &analysis); {
	case execErr == nil:
		analysis.Status = StatusCompleted
	case errors.Is(r.ctx.Err(), context.Canceled):
		// The server is going down. Say so plainly rather than leaving a
		// half-finished analysis looking like a scanner problem.
		analysis.Status = StatusFailed
		analysis.Error = "interrupted: the server shut down mid-analysis"
	default:
		analysis.Status = StatusFailed
		analysis.Error = execErr.Error()
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
	dir, cleanup, err := r.sourceTree(ctx, analysis)
	if err != nil {
		return err
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
	revision := r.resolveRevision(analysis, scanResp.Scan.Revision())

	agg := usecases.NewAggregateFindings().Execute(dto.AggregateFindingsRequest{
		Inputs:       [][]finding.Finding{scanResp.Findings},
		CrossScanner: r.cfg.CrossScannerDedup(),
	})
	analysis.Findings = len(agg.Findings)
	analysis.BySeverity = countBySeverity(agg.Findings)

	doc, writeErr := r.writeSARIF(ctx, codec, analysis, revision, agg.Findings)
	if writeErr != nil {
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

	if err := r.reconcile(ctx, analysis, agg.Findings); err != nil {
		return err
	}

	// Publishing is the last step and never fails the analysis: the findings
	// are already stored and served here. GitHub makes them visible in the
	// repository; the platform gives them a lifecycle and a triage queue.
	r.publishToGitHub(ctx, *analysis, doc)
	r.publishToPlatform(ctx, *analysis, doc)
	return nil
}

// publishToPlatform files the analysis in VektCore_Platform, where a finding
// gets a status, an owner and a triage decision. Cortex remains the record of
// what the scan found; the platform becomes the record of what was decided.
//
// Every failure here is logged and swallowed, for the same reason as the GitHub
// publisher: a platform that is down, or a token that has expired, must not
// turn a completed scan into a failed one.
func (r *Runner) publishToPlatform(ctx context.Context, analysis Analysis, sarif []byte) {
	cfg := r.cfg.Server.Platform
	client := platformpublish.New(cfg.BaseURL, cfg.Token)
	if !client.Configured() {
		return
	}

	// The platform addresses projects by UUID and cortex by name, and neither
	// can derive the other. An unmapped project is skipped and said out loud,
	// because silently not publishing looks exactly like publishing.
	projectID, ok := cfg.PlatformProjectID(analysis.Project)
	if !ok {
		r.logger.Warn("not publishing to the platform: no project mapping",
			ports.F("id", analysis.ID),
			ports.F("project", analysis.Project),
			ports.F("fix", "add server.platform.projects."+analysis.Project))
		return
	}

	result, err := client.PublishScan(ctx, platformpublish.ScanRequest{
		ProjectID:      projectID,
		Commit:         analysis.Commit,
		Ref:            analysis.Ref,
		AnalysisID:     analysis.ID,
		ScannerVersion: r.cfg.Server.EngineVersion,
		SARIF:          sarif,
	})
	if err != nil {
		r.logger.Warn("could not publish to the platform",
			ports.F("id", analysis.ID), ports.F("error", err.Error()))
		return
	}

	// The platform's counts are post-deduplication and post-triage-replay, so
	// they legitimately differ from this analysis's own. Logged as the
	// platform's view, never reconciled against ours.
	r.logger.Info("analysis published to the platform",
		ports.F("id", analysis.ID),
		ports.F("platform_scan", result.ScanID),
		ports.F("platform_total", fmt.Sprint(result.TotalFindings)),
		ports.F("platform_new", fmt.Sprint(result.NewFindings)))
}

// sourceTree produces the directory to analyse, and a cleanup that removes it.
//
// The two shapes differ in who holds the code. A git analysis means the server
// was granted access and clones. An upload means the client's pipeline sent the
// tree and the server never touches their forge at all.
func (r *Runner) sourceTree(
	ctx context.Context, analysis *Analysis,
) (string, func(), error) {
	if analysis.Source == SourceUpload {
		return r.expandArchive(analysis)
	}

	dir, cleanup, err := gitinfra.Clone(ctx, gitinfra.CloneSpec{
		URL: analysis.Repository,
		Ref: analysis.Ref,
	})
	if err != nil {
		return "", func() {}, fmt.Errorf("clone: %w", err)
	}
	return dir, cleanup, nil
}

// expandArchive unpacks an uploaded archive under the data directory rather
// than /tmp, which in a container is often small or memory-backed.
func (r *Runner) expandArchive(analysis *Analysis) (string, func(), error) {
	cfg := r.cfg.Server.Upload

	res, cleanup, err := archive.ExtractZip(
		r.store.ArchivePath(analysis.ID),
		r.store.WorkDir(),
		archive.Limits{MaxEntries: cfg.MaxEntries, MaxBytes: cfg.MaxExtractedBytes},
	)
	if err != nil {
		return "", func() {}, fmt.Errorf("archive: %w", err)
	}

	// A dropped symlink is source the scanners did not see, so it is on the
	// record rather than only in the extractor.
	if res.SkippedLinks > 0 {
		analysis.Error = fmt.Sprintf(
			"%d symlink(s) in the archive were not extracted", res.SkippedLinks)
	}
	r.logger.Info("archive expanded",
		ports.F("id", analysis.ID),
		ports.F("files", fmt.Sprint(res.Files)),
		ports.F("bytes", fmt.Sprint(res.Bytes)),
		ports.F("skipped_links", fmt.Sprint(res.SkippedLinks)))

	return res.Dir, cleanup, nil
}

// resolveRevision decides which revision the results are stamped with.
//
// A clone carries its own and is authoritative. An uploaded tree has no .git,
// so the only revision available is the one the pipeline declared — and if it
// declared none, the scan honestly reports an unknown revision rather than
// inventing one.
func (r *Runner) resolveRevision(analysis *Analysis, scanned scan.Revision) scan.Revision {
	if analysis.Source != SourceUpload {
		analysis.Commit = scanned.Commit()
		if analysis.Ref == "" {
			analysis.Ref = scanned.Branch()
		}
		return scanned
	}

	if analysis.Commit == "" {
		return scan.UnknownRevision()
	}
	revision, err := scan.NewRevision(analysis.Commit, analysis.Ref).Get()
	if err != nil {
		r.logger.Warn("declared revision rejected",
			ports.F("id", analysis.ID), ports.F("error", err.Error()))
		return scan.UnknownRevision()
	}
	return revision
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
	ctx context.Context,
	codec ports.SarifCodec,
	analysis *Analysis,
	revision scan.Revision,
	deduped []finding.Finding,
) ([]byte, error) {
	doc, err := codec.Write(deduped, ports.SarifMetadata{
		Tool:     "cortex",
		Revision: revision,
	}).Get()
	if err != nil {
		return nil, fmt.Errorf("write SARIF: %w", err)
	}
	if writeErr := r.records.WriteSARIF(ctx, analysis.ID, doc); writeErr != nil {
		return nil, fmt.Errorf("store SARIF: %w", writeErr)
	}
	return doc, nil
}

// publishToGitHub writes the outcome back into the analysed repository: the
// findings as Code Scanning alerts, the verdict as a commit status.
//
// Every failure here is logged and swallowed. The analysis succeeded; a token
// without the right scope, or a private repository without GitHub Advanced
// Security, must not turn a completed scan into a failed one.
func (r *Runner) publishToGitHub(ctx context.Context, analysis Analysis, sarif []byte) {
	cfg := r.cfg.Server.GitHub
	client := ghpublish.New(cfg.APIURL, cfg.Token)
	if !client.Configured() {
		return
	}

	owner, repo, ok := ghpublish.SlugFromURL(analysis.Repository)
	if !ok {
		return // not a GitHub repository; nothing to publish to
	}
	if analysis.Commit == "" {
		r.logger.Info("skipping GitHub publication: no commit to attach to",
			ports.F("id", analysis.ID))
		return
	}

	r.uploadAlerts(ctx, client, analysis, owner, repo, sarif)

	if err := client.SetCommitStatus(ctx, ghpublish.StatusRequest{
		Owner:       owner,
		Repo:        repo,
		Commit:      analysis.Commit,
		Passed:      analysis.Gate == "passed",
		Description: statusDescription(analysis),
		TargetURL:   analysisURL(cfg.PublicURL, analysis.ID),
	}); err != nil {
		r.logger.Warn("could not set the commit status",
			ports.F("id", analysis.ID), ports.F("error", err.Error()))
	}
}

// uploadAlerts publishes the findings as Code Scanning alerts.
//
// Separate from the commit status because the two need different things: the
// status needs only a commit, while an alert has to be attached to a branch.
// A missing branch used to skip both, which silently dropped the verdict too.
func (r *Runner) uploadAlerts(
	ctx context.Context,
	client *ghpublish.Client,
	analysis Analysis,
	owner, repo string,
	sarif []byte,
) {
	ref := qualifyRef(analysis.Ref)
	if ref == "" {
		r.logger.Info("skipping Code Scanning: no branch to attach the alerts to",
			ports.F("id", analysis.ID), ports.F("ref", analysis.Ref))
		return
	}

	if err := client.UploadSARIF(ctx, ghpublish.UploadRequest{
		Owner:  owner,
		Repo:   repo,
		Commit: analysis.Commit,
		Ref:    ref,
		SARIF:  sarif,
	}); err != nil {
		r.logger.Warn("could not upload findings to Code Scanning",
			ports.F("id", analysis.ID), ports.F("error", err.Error()))
		return
	}
	r.logger.Info("findings published to Code Scanning",
		ports.F("id", analysis.ID), ports.F("repository", owner+"/"+repo))
}

// qualifyRef turns what the caller gave us into a ref GitHub will accept.
//
// A pipeline that wants the exact commit it is building sends a SHA, which is
// the right thing to send and the wrong thing to prefix with refs/heads/: the
// resulting "refs/heads/<sha>" names no branch and the upload is rejected.
// Such a ref is reported as absent instead, so the commit status still lands.
func qualifyRef(ref string) string {
	ref = strings.TrimSpace(ref)
	switch {
	case ref == "":
		return ""
	case strings.HasPrefix(ref, "refs/"):
		return ref
	case looksLikeCommitSHA(ref):
		return ""
	default:
		return "refs/heads/" + ref
	}
}

// looksLikeCommitSHA reports whether ref is a hex object name rather than a
// branch. Git allows abbreviations, so anything from seven hex characters up
// is treated as one — a branch named "abc1234" is possible but pathological.
func looksLikeCommitSHA(ref string) bool {
	if len(ref) < 7 || len(ref) > 64 {
		return false
	}
	for _, c := range ref {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

// statusDescription is the one line a developer reads next to the commit.
func statusDescription(a Analysis) string {
	if a.KnownBefore == 0 {
		return fmt.Sprintf("%d finding(s) across %d scanner(s)", a.Findings, a.ScannersRan)
	}
	return fmt.Sprintf("%d new, %d total, %d scanner(s)",
		a.NewFindings, a.Findings, a.ScannersRan)
}

func analysisURL(publicURL, id string) string {
	if publicURL == "" {
		return ""
	}
	return strings.TrimRight(publicURL, "/") + "/api/v1/analyses/" + id
}

func (r *Runner) escalations() map[finding.CWE]shared.Severity {
	escalations, err := r.cfg.SeverityEscalations()
	if err != nil {
		r.logger.Warn("severity escalations ignored", ports.F("error", err.Error()))
		return nil
	}
	return escalations
}

// persist records the analysis. It uses a background context deliberately: the
// save that records a failed or interrupted run must still happen when the
// context that carried the scan is exactly what was cancelled.
func (r *Runner) persist(a Analysis) {
	if err := r.records.SaveAnalysis(context.Background(), a); err != nil {
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
