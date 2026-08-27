package usecases

import (
	"context"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/ruleset"
	"github.com/vektcore/cortex/internal/domain/scan"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// ExecuteScan drives scanners against a target path and produces a
// completed Scan aggregate plus the union of findings.
//
// Scanner errors are isolated: one scanner failing never aborts the
// others, and never fails the overall use case — the errors surface in
// the response so the caller can decide how to react.
type ExecuteScan struct {
	registry ports.ScannerRegistry
	detector ports.LanguageDetector
	git      ports.GitRepository
	idGen    ports.IDGenerator
	clock    shared.Clock
	logger   ports.Logger
	// symbols is optional: without it findings simply carry no symbol
	// fingerprint, and matching across refactors degrades to the file level.
	symbols ports.SymbolResolver
	// reach is optional: without it every finding stays "reachability unknown".
	reach ports.ReachabilityAnalyzer
}

// ExecuteScanDeps groups the dependencies into a single constructor
// argument for readability.
type ExecuteScanDeps struct {
	Registry ports.ScannerRegistry
	Detector ports.LanguageDetector
	Git      ports.GitRepository
	IDGen    ports.IDGenerator
	Clock    shared.Clock
	Logger   ports.Logger
	Symbols  ports.SymbolResolver
	Reach    ports.ReachabilityAnalyzer
}

// NewExecuteScan wires the use case.
func NewExecuteScan(d ExecuteScanDeps) *ExecuteScan {
	return &ExecuteScan{
		registry: d.Registry,
		detector: d.Detector,
		git:      d.Git,
		idGen:    d.IDGen,
		clock:    d.Clock,
		logger:   d.Logger,
		symbols:  d.Symbols,
		reach:    d.Reach,
	}
}

// Execute runs the configured scanners in parallel.
func (uc *ExecuteScan) Execute(
	ctx context.Context,
	req dto.ExecuteScanRequest,
) mo.Result[dto.ExecuteScanResponse] {
	rev := uc.resolveRevision(ctx, req.TargetPath)

	languages, err := uc.resolveLanguages(ctx, req)
	if err != nil {
		return shared.Err[dto.ExecuteScanResponse](err)
	}

	scanners := uc.resolveScanners(req.Scanners, languages)

	s := scan.New(uc.idGen.NewScanID(), rev)
	running, err := s.Start(uc.clock.Now()).Get()
	if err != nil {
		return shared.Err[dto.ExecuteScanResponse](err)
	}

	findings, perScanner, errs := uc.runAll(ctx, scanners, req, languages)
	findings = uc.normalize(ctx, req, findings)

	fps := make([]finding.Fingerprint, len(findings))
	for i, f := range findings {
		fps[i] = f.Fingerprint()
	}

	completed, err := running.Complete(uc.clock.Now(), fps).Get()
	if err != nil {
		return shared.Err[dto.ExecuteScanResponse](err)
	}

	uc.logger.Info("scan completed",
		ports.F("scan_id", completed.ID().String()),
		ports.F("findings", len(findings)),
		ports.F("scanner_errors", len(errs)),
	)

	return shared.Ok(dto.ExecuteScanResponse{
		Scan:       completed,
		Findings:   findings,
		PerScanner: perScanner,
		Errors:     errs,
	})
}

// normalize turns raw scanner output into comparable findings. Order matters:
//
//  1. paths first, so every later step and every consumer (gate path rules,
//     allowlist, baseline diff) sees the same stable, relative path;
//  2. CWE enrichment, because severity escalation keys off the CWE;
//  3. severity escalation;
//  4. path exclusion last, as the backstop for scanners whose own exclude
//     flag does not cover a pattern.
func (uc *ExecuteScan) normalize(
	ctx context.Context, req dto.ExecuteScanRequest, findings []finding.Finding,
) []finding.Finding {
	roots := []string{req.TargetPath}
	if abs, err := filepath.Abs(req.TargetPath); err == nil {
		roots = append(roots, abs)
	}

	out := finding.Relativize(findings, roots)
	out = uc.resolveSymbols(ctx, req.TargetPath, out)
	out = ruleset.EnrichCWE(out)
	out = ruleset.Escalate(out, req.Escalations)
	out = uc.applyReachability(ctx, req, out)

	before := len(out)
	out = finding.ExcludePaths(out, req.Exclude)
	if excluded := before - len(out); excluded > 0 {
		uc.logger.Debug("findings excluded by path",
			ports.F("count", excluded))
	}
	return out
}

// resolveSymbols attaches the enclosing function or class to each finding. That
// is what gives the finding its third identity, the one that survives the
// function being moved — without it a refactor looks like a wave of new
// findings and the team's triage is lost.
func (uc *ExecuteScan) resolveSymbols(
	ctx context.Context, root string, findings []finding.Finding,
) []finding.Finding {
	if uc.symbols == nil || len(findings) == 0 {
		return findings
	}

	out := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		symbol, ok := uc.symbols.Resolve(
			ctx, root, f.Location().File(), f.Location().StartLine()).Get()
		if !ok || symbol == "" {
			out = append(out, f)
			continue
		}
		out = append(out, f.WithSymbol(symbol))
	}
	return out
}

// applyReachability labels findings by whether anything calls the code they sit
// in, and demotes the ones in dead code when asked.
//
// It runs after escalation on purpose: escalation decides what the weakness
// would cost if exploited, reachability decides how likely that is. Doing it the
// other way round would let a demotion be undone.
func (uc *ExecuteScan) applyReachability(
	ctx context.Context, req dto.ExecuteScanRequest, findings []finding.Finding,
) []finding.Finding {
	if uc.reach == nil || !req.Reachability.Enabled || len(findings) == 0 {
		return findings
	}

	refs := make([]ports.SymbolRef, 0, len(findings))
	for _, f := range findings {
		if f.SymbolName() == "" {
			continue
		}
		refs = append(refs, ports.SymbolRef{Symbol: f.SymbolName(), File: f.Location().File()})
	}
	if len(refs) == 0 {
		return findings
	}

	unreachable, err := uc.reach.UnreachableSymbols(ctx, req.TargetPath, refs).Get()
	if err != nil {
		uc.logger.Warn("reachability analysis failed, findings stay unlabelled",
			ports.F("error", err.Error()))
		return findings
	}

	dead := 0
	for _, isDead := range unreachable {
		if isDead {
			dead++
		}
	}
	uc.logger.Debug("reachability analysed",
		ports.F("symbols", len(unreachable)),
		ports.F("unreachable", dead))

	return ruleset.ApplyReachability(findings, unreachable, req.Reachability.Demote)
}

// resolveRevision reads the git revision of the target. Cortex must be able to
// analyse any directory — a tarball, a vendored copy, a path outside a
// repository — so an unavailable revision degrades to scan.UnknownRevision()
// instead of aborting the scan.
func (uc *ExecuteScan) resolveRevision(ctx context.Context, path string) scan.Revision {
	rev, err := uc.git.CurrentRevision(ctx, path).Get()
	if err == nil {
		return rev
	}
	uc.logger.Warn("git revision unavailable, continuing without it",
		ports.F("path", path),
		ports.F("error", err.Error()))
	return scan.UnknownRevision()
}

func (uc *ExecuteScan) resolveLanguages(
	ctx context.Context, req dto.ExecuteScanRequest,
) ([]shared.Language, error) {
	if len(req.Languages) > 0 {
		return req.Languages, nil
	}
	return uc.detector.Detect(ctx, req.TargetPath, req.Exclude).Get()
}

func (uc *ExecuteScan) resolveScanners(
	requested []finding.ScannerName, languages []shared.Language,
) []ports.Scanner {
	if len(requested) == 0 {
		return uc.registry.ForLanguages(languages)
	}
	out := make([]ports.Scanner, 0, len(requested))
	for _, name := range requested {
		if s, ok := uc.registry.Get(name).Get(); ok {
			out = append(out, s)
		} else {
			uc.logger.Warn("requested scanner not registered",
				ports.F("scanner", string(name)))
		}
	}
	return out
}

// scannerOutcome is the unit emitted by each goroutine.
type scannerOutcome struct {
	name     finding.ScannerName
	findings []finding.Finding
	sarif    []byte
	err      error
}

func (uc *ExecuteScan) runAll(
	ctx context.Context,
	scanners []ports.Scanner,
	req dto.ExecuteScanRequest,
	languages []shared.Language,
) ([]finding.Finding, map[finding.ScannerName][]byte, map[finding.ScannerName]error) {
	parallelism := req.Parallelism
	if parallelism <= 0 {
		parallelism = runtime.NumCPU()
	}

	sem := make(chan struct{}, parallelism)
	outcomes := make(chan scannerOutcome, len(scanners))
	var wg sync.WaitGroup

	for _, sc := range scanners {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			outcomes <- uc.runOne(ctx, sc, req, languages)
		}()
	}
	wg.Wait()
	close(outcomes)

	var all []finding.Finding
	perScanner := make(map[finding.ScannerName][]byte)
	errs := make(map[finding.ScannerName]error)
	for o := range outcomes {
		if o.err != nil {
			errs[o.name] = o.err
			continue
		}
		all = append(all, o.findings...)
		perScanner[o.name] = o.sarif
	}
	return all, perScanner, errs
}

func (uc *ExecuteScan) runOne(
	ctx context.Context,
	sc ports.Scanner,
	req dto.ExecuteScanRequest,
	languages []shared.Language,
) scannerOutcome {
	uc.logger.Debug("scanner invoked", ports.F("scanner", string(sc.Name())))

	settings := req.Settings[sc.Name()]
	r := sc.Scan(ctx, ports.ScanRequest{
		TargetPath: req.TargetPath,
		Languages:  languages,
		Timeout:    settings.Timeout,
		Options:    settings.Options,
		Exclude:    req.Exclude,
	})
	out, err := r.Get()
	if err != nil {
		uc.logger.Warn("scanner failed",
			ports.F("scanner", string(sc.Name())),
			ports.F("error", err.Error()))
		return scannerOutcome{name: sc.Name(), err: err}
	}
	return scannerOutcome{
		name:     out.Scanner,
		findings: out.Findings,
		sarif:    out.RawSARIF,
	}
}
