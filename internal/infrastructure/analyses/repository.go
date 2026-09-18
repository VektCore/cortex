package analyses

import (
	"context"
	"errors"
)

// Errors a caller may want to distinguish.
var (
	// ErrNotFound means no analysis carries that id. Loading reports absence
	// through a boolean instead; this one is for the writes, where there is no
	// sensible record to hand back.
	ErrNotFound = errors.New("no analysis with that id")
	// ErrNoID means a record arrived without an id. The id is what a client
	// polls with, so a row that cannot be addressed is worse than a refused
	// write: nobody would ever find out the analysis happened.
	ErrNoID = errors.New("an analysis must carry an id")
	// ErrNoDSN means no database was configured. This package only speaks to
	// Postgres; the file-backed store still lives in interfaces/httpapi.
	ErrNoDSN = errors.New("no postgres dsn configured")
)

// Repository is where analysis reports, their SARIF and each project's state
// document live.
//
// The shape is deliberately the one a file tree can also satisfy — bytes in,
// bytes out, absence reported separately from failure — so the existing
// directory-backed store can be moved behind it later without the handlers
// changing. Only the Postgres implementation exists here.
type Repository interface {
	// SaveAnalysis writes the record, replacing any previous version of it.
	// An analysis is saved several times as it moves from queued to finished.
	SaveAnalysis(ctx context.Context, report Report) error
	// LoadAnalysis returns one record. A missing id comes back as ok=false and
	// no error, so a handler can answer 404 rather than 500.
	LoadAnalysis(ctx context.Context, id string) (Report, bool, error)
	// ListAnalyses returns records newest first, optionally filtered by
	// project. A limit of zero or less means no limit.
	ListAnalyses(ctx context.Context, project string, limit int) ([]Report, error)
	// WriteSARIF stores the canonical SARIF of an analysis that already exists.
	WriteSARIF(ctx context.Context, id string, doc []byte) error
	// ReadSARIF returns it. An analysis that has not produced one yet is
	// absence, not failure: a client polls a running analysis for exactly that.
	ReadSARIF(ctx context.Context, id string) ([]byte, bool, error)
	// ReadProjectState returns the reconcile history a project's next run
	// compares against. A project that has never been analysed has none.
	ReadProjectState(ctx context.Context, project string) ([]byte, bool, error)
	// WriteProjectState replaces it.
	WriteProjectState(ctx context.Context, project string, doc []byte) error
	// Close releases whatever the implementation holds.
	Close()
}

// Open resolves the configured backend. It exists so every caller — the server
// and any command that reads the same records — goes through one entry point
// and cannot end up writing analyses into a store the server does not read.
//
// An empty DSN is refused rather than silently falling back: this package has
// no file implementation, and returning one that persists nothing would make a
// misconfigured server look healthy until a client asked for a result.
func Open(ctx context.Context, dsn string) (Repository, error) {
	if dsn == "" {
		return nil, ErrNoDSN
	}
	return NewPostgresStore(ctx, dsn)
}
