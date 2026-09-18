package httpapi

import (
	"context"

	"github.com/vektcore/cortex/internal/infrastructure/analyses"
)

// analysisRecords is where analyses and their SARIF are kept.
//
// Two implementations, because the same binary serves two deployments. The
// file one keeps the property that a single binary plus a volume is the whole
// service. The Postgres one is for the server a client's pipeline depends on:
// several instances behind one database, and reports that can be answered with
// a query rather than by listing a directory.
//
// Deliberately narrower than the file Store, which also owns things that have
// no business in a database: the uploaded archive, the directory it is expanded
// into, and the SARIF a client's own CI posts. Those stay on disk either way.
type analysisRecords interface {
	SaveAnalysis(ctx context.Context, a Analysis) error
	LoadAnalysis(ctx context.Context, id string) (Analysis, bool, error)
	// ListAnalyses returns records newest first. owner scopes the listing to
	// one client and is the whole reason a listing is not a directory of
	// every tenant's work; an empty owner means every owner, which only an
	// operator ever gets. project, when set, is the full owner-scoped key.
	ListAnalyses(ctx context.Context, owner, project string, limit int) ([]Analysis, error)
	WriteSARIF(ctx context.Context, id string, doc []byte) error
	ReadSARIF(ctx context.Context, id string) ([]byte, bool, error)
	Close()
}

// fileRecords is the filesystem implementation, which is the existing Store.
type fileRecords struct{ store *Store }

func (f fileRecords) SaveAnalysis(_ context.Context, a Analysis) error {
	return f.store.SaveAnalysis(a)
}

func (f fileRecords) LoadAnalysis(_ context.Context, id string) (Analysis, bool, error) {
	return f.store.LoadAnalysis(id)
}

func (f fileRecords) ListAnalyses(
	_ context.Context, owner, project string, limit int,
) ([]Analysis, error) {
	return f.store.ListAnalyses(owner, project, limit)
}

func (f fileRecords) WriteSARIF(_ context.Context, id string, doc []byte) error {
	return f.store.WriteBlob(f.store.SarifPath(id), doc)
}

func (f fileRecords) ReadSARIF(_ context.Context, id string) ([]byte, bool, error) {
	return f.store.ReadBlob(f.store.SarifPath(id))
}

// Close is a no-op: the file store holds nothing to release, and the server
// closes the Store it wraps separately.
func (f fileRecords) Close() {}

// pgRecords is the PostgreSQL implementation.
//
// Analysis and analyses.Report are the same record in two layers: the
// persistence package cannot import this one without a cycle, so the fields are
// copied across rather than shared. The JSON tags are identical on both sides,
// and a test in the analyses package pins them, because a rename there would
// otherwise change this API without breaking the build.
type pgRecords struct{ repo analyses.Repository }

func (p pgRecords) SaveAnalysis(ctx context.Context, a Analysis) error {
	return p.repo.SaveAnalysis(ctx, reportFrom(a))
}

func (p pgRecords) LoadAnalysis(ctx context.Context, id string) (Analysis, bool, error) {
	report, found, err := p.repo.LoadAnalysis(ctx, id)
	if err != nil || !found {
		return Analysis{}, found, err
	}
	return analysisFrom(report), true, nil
}

func (p pgRecords) ListAnalyses(
	ctx context.Context, owner, project string, limit int,
) ([]Analysis, error) {
	reports, err := p.repo.ListAnalyses(ctx, owner, project, limit)
	if err != nil {
		return nil, err
	}
	out := make([]Analysis, 0, len(reports))
	for _, report := range reports {
		out = append(out, analysisFrom(report))
	}
	return out, nil
}

func (p pgRecords) WriteSARIF(ctx context.Context, id string, doc []byte) error {
	return p.repo.WriteSARIF(ctx, id, doc)
}

func (p pgRecords) ReadSARIF(ctx context.Context, id string) ([]byte, bool, error) {
	return p.repo.ReadSARIF(ctx, id)
}

func (p pgRecords) Close() { p.repo.Close() }

func reportFrom(a Analysis) analyses.Report {
	return analyses.Report{
		ID: a.ID, Owner: a.Owner, Project: a.Project, Source: a.Source,
		Repository: a.Repository, Ref: a.Ref, Commit: a.Commit,
		Status: a.Status, Gate: a.Gate,
		Findings: a.Findings, BySeverity: a.BySeverity,
		NewFindings: a.NewFindings, Reopened: a.Reopened, Resolved: a.Resolved,
		ScannersRan: a.ScannersRan, ScannerErrors: a.ScannerErrors,
		KnownBefore: a.KnownBefore, RequestedBy: a.RequestedBy, Error: a.Error,
		QueuedAt: a.QueuedAt, StartedAt: a.StartedAt, FinishedAt: a.FinishedAt,
	}
}

func analysisFrom(r analyses.Report) Analysis {
	return Analysis{
		ID: r.ID, Owner: r.Owner, Project: r.Project, Source: r.Source,
		Repository: r.Repository, Ref: r.Ref, Commit: r.Commit,
		Status: r.Status, Gate: r.Gate,
		Findings: r.Findings, BySeverity: r.BySeverity,
		NewFindings: r.NewFindings, Reopened: r.Reopened, Resolved: r.Resolved,
		ScannersRan: r.ScannersRan, ScannerErrors: r.ScannerErrors,
		KnownBefore: r.KnownBefore, RequestedBy: r.RequestedBy, Error: r.Error,
		QueuedAt: r.QueuedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
	}
}

// openRecords picks the backend. An empty DSN is the file store, which is what
// lets this binary run with no database in sight.
func openRecords(ctx context.Context, dsn string, store *Store) (analysisRecords, error) {
	if dsn == "" {
		return fileRecords{store: store}, nil
	}
	repo, err := analyses.Open(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return pgRecords{repo: repo}, nil
}
