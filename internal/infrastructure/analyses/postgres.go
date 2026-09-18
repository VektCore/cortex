package analyses

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// schema is applied on connect, and is written to be safe to re-apply: several
// server instances start against the same database, and the second one must
// not fail on tables the first already created.
//
// Cortex carries its own schema rather than joining VektCore_Migrations. That
// orchestrator runs Alembic out of a service's own image, and a Go binary has
// neither Alembic nor SQLAlchemy in it.
//
// The SARIF lives in a BYTEA column on the analysis row rather than in a file
// or a second table. Postgres TOASTs a value that large out of line, so a
// multi-megabyte document costs nothing on the queries that do not select it,
// and the report and its evidence are then written and dropped together — no
// row can outlive its document or the other way round.
const schema = `
CREATE TABLE IF NOT EXISTS cortex_analyses (
    id             TEXT PRIMARY KEY,
    project        TEXT NOT NULL,
    source         TEXT NOT NULL,
    repository     TEXT NOT NULL DEFAULT '',
    ref            TEXT NOT NULL DEFAULT '',
    commit_sha     TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL,
    gate           TEXT NOT NULL DEFAULT '',
    findings       INTEGER NOT NULL DEFAULT 0,
    by_severity    JSONB,
    new_findings   INTEGER NOT NULL DEFAULT 0,
    reopened       INTEGER NOT NULL DEFAULT 0,
    resolved       INTEGER NOT NULL DEFAULT 0,
    known_before   INTEGER NOT NULL DEFAULT 0,
    scanners_ran   INTEGER NOT NULL DEFAULT 0,
    scanner_errors JSONB,
    requested_by   TEXT NOT NULL DEFAULT '',
    error          TEXT NOT NULL DEFAULT '',
    queued_at      TIMESTAMPTZ NOT NULL,
    started_at     TIMESTAMPTZ,
    finished_at    TIMESTAMPTZ,
    sarif          BYTEA
);
CREATE INDEX IF NOT EXISTS cortex_analyses_project_idx
    ON cortex_analyses (project, queued_at DESC);
CREATE INDEX IF NOT EXISTS cortex_analyses_queued_idx
    ON cortex_analyses (queued_at DESC);

CREATE TABLE IF NOT EXISTS cortex_project_state (
    project    TEXT PRIMARY KEY,
    document   BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
`

// analysisColumns is shared by every read so the order the scanner expects is
// stated once. sarif is deliberately absent: a listing that selected it would
// pull every SARIF the project ever produced through the connection to show a
// page of counts.
const analysisColumns = `
    id, project, source, repository, ref, commit_sha, status, gate,
    findings, by_severity, new_findings, reopened, resolved, known_before,
    scanners_ran, scanner_errors, requested_by, error,
    queued_at, started_at, finished_at`

// upsertAnalysisStmt replaces the record on conflict because an analysis is
// saved again at every transition — queued, running, finished. The update list
// omits sarif on purpose: it is written by WriteSARIF, and re-saving the record
// afterwards (to set finished_at, say) would otherwise blank the document the
// run just produced.
const upsertAnalysisStmt = `
INSERT INTO cortex_analyses (
    id, project, source, repository, ref, commit_sha, status, gate,
    findings, by_severity, new_findings, reopened, resolved, known_before,
    scanners_ran, scanner_errors, requested_by, error,
    queued_at, started_at, finished_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8,
    $9, $10, $11, $12, $13, $14,
    $15, $16, $17, $18,
    $19, $20, $21
)
ON CONFLICT (id) DO UPDATE SET
    project = EXCLUDED.project,
    source = EXCLUDED.source,
    repository = EXCLUDED.repository,
    ref = EXCLUDED.ref,
    commit_sha = EXCLUDED.commit_sha,
    status = EXCLUDED.status,
    gate = EXCLUDED.gate,
    findings = EXCLUDED.findings,
    by_severity = EXCLUDED.by_severity,
    new_findings = EXCLUDED.new_findings,
    reopened = EXCLUDED.reopened,
    resolved = EXCLUDED.resolved,
    known_before = EXCLUDED.known_before,
    scanners_ran = EXCLUDED.scanners_ran,
    scanner_errors = EXCLUDED.scanner_errors,
    requested_by = EXCLUDED.requested_by,
    error = EXCLUDED.error,
    queued_at = EXCLUDED.queued_at,
    started_at = EXCLUDED.started_at,
    finished_at = EXCLUDED.finished_at`

// PostgresStore keeps analysis reports in a database.
//
// This is the store for the server deployment: several instances behind one
// database, where a result has to be readable by whichever instance the client
// happens to poll. The file store remains the answer for a single binary plus
// a volume.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore connects and applies the schema.
func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	if pingErr := pool.Ping(ctx); pingErr != nil {
		pool.Close()
		return nil, fmt.Errorf("reach postgres: %w", pingErr)
	}
	if _, execErr := pool.Exec(ctx, schema); execErr != nil {
		pool.Close()
		return nil, fmt.Errorf("apply analysis schema: %w", execErr)
	}
	return &PostgresStore{pool: pool}, nil
}

// Close releases the pool.
func (s *PostgresStore) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// SaveAnalysis writes the record, replacing any previous version.
func (s *PostgresStore) SaveAnalysis(ctx context.Context, report Report) error {
	if report.ID == "" {
		return ErrNoID
	}

	bySeverity, err := encodeMap(report.BySeverity)
	if err != nil {
		return fmt.Errorf("encode severities of %s: %w", report.ID, err)
	}
	scannerErrors, err := encodeMap(report.ScannerErrors)
	if err != nil {
		return fmt.Errorf("encode scanner errors of %s: %w", report.ID, err)
	}

	_, err = s.pool.Exec(ctx, upsertAnalysisStmt,
		report.ID, report.Project, report.Source, report.Repository, report.Ref,
		report.Commit, report.Status, report.Gate,
		report.Findings, bySeverity, report.NewFindings, report.Reopened,
		report.Resolved, report.KnownBefore,
		report.ScannersRan, scannerErrors, report.RequestedBy, report.Error,
		report.QueuedAt.UTC(), utc(report.StartedAt), utc(report.FinishedAt))
	if err != nil {
		return fmt.Errorf("store analysis %s: %w", report.ID, err)
	}
	return nil
}

// LoadAnalysis returns one record, reporting a missing id as absence so the
// handler can answer 404 rather than 500.
func (s *PostgresStore) LoadAnalysis(ctx context.Context, id string) (Report, bool, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT`+analysisColumns+` FROM cortex_analyses WHERE id = $1`, id)

	report, err := scanReport(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Report{}, false, nil
	}
	if err != nil {
		return Report{}, false, fmt.Errorf("read analysis %s: %w", id, err)
	}
	return report, true, nil
}

// ListAnalyses returns records newest first. An empty project means every
// project, and a limit of zero or less means no limit — passed as SQL NULL,
// which LIMIT reads as "all", rather than by building a second statement.
func (s *PostgresStore) ListAnalyses(
	ctx context.Context, project string, limit int,
) ([]Report, error) {
	var pageLimit *int
	if limit > 0 {
		pageLimit = &limit
	}

	rows, err := s.pool.Query(ctx,
		`SELECT`+analysisColumns+`
		FROM cortex_analyses
		WHERE $1 = '' OR project = $1
		ORDER BY queued_at DESC, id DESC
		LIMIT $2`, project, pageLimit)
	if err != nil {
		return nil, fmt.Errorf("list analyses: %w", err)
	}
	defer rows.Close()

	reports := make([]Report, 0, 16)
	for rows.Next() {
		report, scanErr := scanReport(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("read analysis: %w", scanErr)
		}
		reports = append(reports, report)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("list analyses: %w", rows.Err())
	}
	return reports, nil
}

// WriteSARIF attaches the document to an analysis that already exists. An
// unknown id is an error rather than an insert: fabricating a row here would
// leave a report nobody queued, and silently updating nothing would leave a
// finished analysis with no document and no complaint to show for it.
func (s *PostgresStore) WriteSARIF(ctx context.Context, id string, doc []byte) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE cortex_analyses SET sarif = $2 WHERE id = $1`, id, doc)
	if err != nil {
		return fmt.Errorf("store sarif for %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return nil
}

// ReadSARIF returns the stored document. Both an unknown analysis and one that
// has not produced a document yet are absence: a client polling a running
// analysis asks for exactly this and must not get a 500 for it.
func (s *PostgresStore) ReadSARIF(ctx context.Context, id string) ([]byte, bool, error) {
	var doc []byte
	err := s.pool.QueryRow(ctx,
		`SELECT sarif FROM cortex_analyses WHERE id = $1`, id).Scan(&doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read sarif for %s: %w", id, err)
	}
	// A NULL column scans to nil, an empty document to an empty slice; only
	// the first means the analysis has produced nothing yet.
	return doc, doc != nil, nil
}

// ReadProjectState returns the project's reconcile history.
func (s *PostgresStore) ReadProjectState(
	ctx context.Context, project string,
) ([]byte, bool, error) {
	var doc []byte
	err := s.pool.QueryRow(ctx,
		`SELECT document FROM cortex_project_state WHERE project = $1`, project).Scan(&doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read state of project %s: %w", project, err)
	}
	return doc, true, nil
}

// WriteProjectState replaces the project's document.
//
// The primary key is the project, so each one keeps its own history. Sharing a
// row would make every finding of the next project look new and every finding
// of the previous one resolved. The document is stored as bytes, not JSONB,
// because it is written and read back whole: JSONB would reorder its keys and
// drop duplicates, and the bytes that came out would not be the bytes that
// went in.
func (s *PostgresStore) WriteProjectState(
	ctx context.Context, project string, doc []byte,
) error {
	if project == "" {
		return errors.New("project state needs a project name")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO cortex_project_state (project, document, updated_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (project) DO UPDATE SET
			document = EXCLUDED.document,
			updated_at = EXCLUDED.updated_at`,
		project, doc, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("store state of project %s: %w", project, err)
	}
	return nil
}

// scanRow is what both QueryRow and Rows satisfy, so one scanner serves both.
type scanRow interface {
	Scan(dest ...any) error
}

func scanReport(row scanRow) (Report, error) {
	var report Report
	var bySeverity, scannerErrors []byte
	var started, finished *time.Time

	if err := row.Scan(
		&report.ID, &report.Project, &report.Source, &report.Repository, &report.Ref,
		&report.Commit, &report.Status, &report.Gate,
		&report.Findings, &bySeverity, &report.NewFindings, &report.Reopened,
		&report.Resolved, &report.KnownBefore,
		&report.ScannersRan, &scannerErrors, &report.RequestedBy, &report.Error,
		&report.QueuedAt, &started, &finished,
	); err != nil {
		return Report{}, err
	}

	if err := decodeMap(bySeverity, &report.BySeverity); err != nil {
		return Report{}, fmt.Errorf("severities of %s: %w", report.ID, err)
	}
	if err := decodeMap(scannerErrors, &report.ScannerErrors); err != nil {
		return Report{}, fmt.Errorf("scanner errors of %s: %w", report.ID, err)
	}
	report.StartedAt, report.FinishedAt = started, finished
	return report, nil
}

// encodeMap keeps an absent map absent. Writing it as "{}" would turn "no
// severity breakdown was recorded" into "the breakdown is empty", and the two
// say different things to a client deciding whether a scan produced anything.
func encodeMap[V any](m map[string]V) ([]byte, error) {
	if m == nil {
		return []byte(nil), nil
	}
	return json.Marshal(m)
}

// decodeMap is the other half: a NULL column leaves the field nil rather than
// allocating an empty map, so a record survives the round trip unchanged.
func decodeMap(raw []byte, dst any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, dst)
}

// utc normalises an optional timestamp. The column is TIMESTAMPTZ, so the zone
// is not stored; converting here keeps what a test compares and what a log
// prints in one zone instead of the server's.
func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// compile-time proof that the postgres store is a Repository.
var _ Repository = (*PostgresStore)(nil)
