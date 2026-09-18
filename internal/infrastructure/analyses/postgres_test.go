//go:build integration

package analyses_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/infrastructure/analyses"
)

// newPostgres skips rather than fails when there is no database: the unit
// suite has to stay runnable on a laptop with nothing installed.
func newPostgres(t *testing.T) analyses.Repository {
	t.Helper()

	dsn := os.Getenv("CORTEX_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set CORTEX_TEST_POSTGRES_DSN to run the postgres tests")
	}

	store, err := analyses.NewPostgresStore(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(store.Close)
	return store
}

// unique keeps one test's rows out of another's reach. The database outlives
// the run, so a fixed id would pass once and then collide with itself.
func unique(t *testing.T, prefix string) string {
	t.Helper()
	return fmt.Sprintf("%s-%s-%d", prefix, t.Name(), time.Now().UnixNano())
}

// Postgres keeps microseconds; a nanosecond-precision time would come back
// rounded and every equality assertion would be about the clock, not the store.
func storedNow() time.Time {
	return time.Now().UTC().Truncate(time.Microsecond)
}

// The schema is applied on every connect, so a second server starting against
// the same database must not fail on tables that already exist.
func TestPostgres_SchemaIsReapplicable(t *testing.T) {
	first := newPostgres(t)
	require.NotNil(t, first)

	second := newPostgres(t)
	assert.NotNil(t, second)
}

func TestPostgres_SaveAndLoadRoundTrip(t *testing.T) {
	store := newPostgres(t)
	ctx := context.Background()
	queued := storedNow()
	started := queued.Add(time.Second)
	finished := queued.Add(time.Minute)

	want := analyses.Report{
		ID:            unique(t, "an"),
		Project:       unique(t, "proj"),
		Source:        "git",
		Repository:    "git@example.com:acme/app.git",
		Ref:           "refs/heads/main",
		Commit:        "0f1e2d3c",
		Status:        "completed",
		Gate:          "failed",
		Findings:      12,
		BySeverity:    map[string]int{"critical": 2, "high": 4, "low": 6},
		NewFindings:   3,
		Reopened:      1,
		Resolved:      5,
		ScannersRan:   4,
		ScannerErrors: map[string]string{"gosec": "exit status 3"},
		KnownBefore:   9,
		RequestedBy:   "ci@acme",
		Error:         "",
		QueuedAt:      queued,
		StartedAt:     &started,
		FinishedAt:    &finished,
	}
	require.NoError(t, store.SaveAnalysis(ctx, want))

	got, found, err := store.LoadAnalysis(ctx, want.ID)
	require.NoError(t, err)
	require.True(t, found)

	got.QueuedAt = got.QueuedAt.UTC()
	assert.Equal(t, want.QueuedAt, got.QueuedAt)
	require.NotNil(t, got.StartedAt)
	require.NotNil(t, got.FinishedAt)
	assert.Equal(t, started, got.StartedAt.UTC())
	assert.Equal(t, finished, got.FinishedAt.UTC())

	got.QueuedAt, got.StartedAt, got.FinishedAt = want.QueuedAt, want.StartedAt, want.FinishedAt
	assert.Equal(t, want, got)
}

// A record with no severity breakdown must not come back with an empty one:
// "nothing was recorded" and "the breakdown is empty" are different answers,
// and only the first one is honest about a scan that produced no aggregation.
func TestPostgres_AbsentMapsSurviveAsAbsent(t *testing.T) {
	store := newPostgres(t)
	ctx := context.Background()

	id := unique(t, "an")
	require.NoError(t, store.SaveAnalysis(ctx, analyses.Report{
		ID: id, Project: unique(t, "proj"), Source: "upload",
		Status: "queued", QueuedAt: storedNow(),
	}))

	got, found, err := store.LoadAnalysis(ctx, id)
	require.NoError(t, err)
	require.True(t, found)

	assert.Nil(t, got.BySeverity)
	assert.Nil(t, got.ScannerErrors)
	assert.Nil(t, got.StartedAt)
	assert.Nil(t, got.FinishedAt)
}

// A handler has to be able to answer 404. An unknown id is absence, not a
// failure to read the database.
func TestPostgres_LoadUnknownIDIsAbsenceNotError(t *testing.T) {
	store := newPostgres(t)

	got, found, err := store.LoadAnalysis(context.Background(), "nosuchanalysis")

	require.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, analyses.Report{}, got)
}

func TestPostgres_SaveWithoutAnID(t *testing.T) {
	store := newPostgres(t)

	err := store.SaveAnalysis(context.Background(), analyses.Report{
		Project: "acme", Status: "queued", QueuedAt: storedNow(),
	})

	require.ErrorIs(t, err, analyses.ErrNoID)
}

// The record is saved again at every transition. The save that records
// finished_at happens after the SARIF was written, so an upsert that carried
// the whole row would blank the document the run just produced.
func TestPostgres_ResavingTheRecordKeepsTheSARIF(t *testing.T) {
	store := newPostgres(t)
	ctx := context.Background()
	queued := storedNow()

	id := unique(t, "an")
	report := analyses.Report{
		ID: id, Project: unique(t, "proj"), Source: "git",
		Status: "running", QueuedAt: queued,
	}
	require.NoError(t, store.SaveAnalysis(ctx, report))
	require.NoError(t, store.WriteSARIF(ctx, id, []byte(`{"version":"2.1.0"}`)))

	finished := queued.Add(time.Minute)
	report.Status = "completed"
	report.Gate = "passed"
	report.FinishedAt = &finished
	require.NoError(t, store.SaveAnalysis(ctx, report))

	doc, found, err := store.ReadSARIF(ctx, id)
	require.NoError(t, err)
	require.True(t, found, "the second save must not blank the document")
	assert.JSONEq(t, `{"version":"2.1.0"}`, string(doc))

	got, _, err := store.LoadAnalysis(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, "completed", got.Status)
	assert.Equal(t, "passed", got.Gate)
	require.NotNil(t, got.FinishedAt)
}

func TestPostgres_ListIsNewestFirstAndScopedToTheProject(t *testing.T) {
	store := newPostgres(t)
	ctx := context.Background()
	project := unique(t, "proj")
	other := unique(t, "other")
	base := storedNow()

	var wantNewestFirst []string
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("%s-%d", unique(t, "an"), i)
		require.NoError(t, store.SaveAnalysis(ctx, analyses.Report{
			ID: id, Project: project, Source: "git", Status: "completed",
			QueuedAt: base.Add(time.Duration(i) * time.Minute),
		}))
		wantNewestFirst = append([]string{id}, wantNewestFirst...)
	}
	require.NoError(t, store.SaveAnalysis(ctx, analyses.Report{
		ID: unique(t, "an"), Project: other, Source: "git", Status: "completed",
		QueuedAt: base.Add(time.Hour),
	}))

	listed, err := store.ListAnalyses(ctx, "", project, 0)
	require.NoError(t, err)
	require.Len(t, listed, 3, "a project's listing must not see another project's runs")

	ids := make([]string, 0, len(listed))
	for _, report := range listed {
		ids = append(ids, report.ID)
	}
	assert.Equal(t, wantNewestFirst, ids)

	capped, err := store.ListAnalyses(ctx, "", project, 2)
	require.NoError(t, err)
	require.Len(t, capped, 2)
	assert.Equal(t, wantNewestFirst[:2], []string{capped[0].ID, capped[1].ID},
		"a limit must cut the oldest, not an arbitrary page")
}

// An empty project means every project — the operator-facing listing.
func TestPostgres_ListWithoutAProjectSpansThemAll(t *testing.T) {
	store := newPostgres(t)
	ctx := context.Background()

	first := unique(t, "an")
	second := unique(t, "an")
	now := storedNow()
	require.NoError(t, store.SaveAnalysis(ctx, analyses.Report{
		ID: first, Project: unique(t, "projA"), Source: "git",
		Status: "completed", QueuedAt: now,
	}))
	require.NoError(t, store.SaveAnalysis(ctx, analyses.Report{
		ID: second, Project: unique(t, "projB"), Source: "git",
		Status: "completed", QueuedAt: now.Add(time.Second),
	}))

	listed, err := store.ListAnalyses(ctx, "", "", 50)
	require.NoError(t, err)

	seen := map[string]bool{}
	for _, report := range listed {
		seen[report.ID] = true
	}
	assert.True(t, seen[first])
	assert.True(t, seen[second])
}

// The owner filter is what keeps one client's listing out of another's. It is
// asserted at this level and not only at the HTTP one because it is applied in
// SQL: a handler that forgot to pass an owner must come back empty-handed, not
// with the whole table.
func TestPostgres_ListIsScopedToTheOwner(t *testing.T) {
	store := newPostgres(t)
	ctx := context.Background()
	alice, bob := unique(t, "alice"), unique(t, "bob")
	// The same project name under two owners, which is the collision a global
	// project namespace used to merge into one history.
	name := unique(t, "shared")
	now := storedNow()

	hers, his := unique(t, "an"), unique(t, "an")
	require.NoError(t, store.SaveAnalysis(ctx, analyses.Report{
		ID: hers, Owner: alice, Project: alice + "/" + name, Source: "git",
		Status: "completed", QueuedAt: now,
	}))
	require.NoError(t, store.SaveAnalysis(ctx, analyses.Report{
		ID: his, Owner: bob, Project: bob + "/" + name, Source: "git",
		Status: "completed", QueuedAt: now.Add(time.Second),
	}))

	forAlice, err := store.ListAnalyses(ctx, alice, "", 50)
	require.NoError(t, err)
	require.Len(t, forAlice, 1)
	assert.Equal(t, hers, forAlice[0].ID)
	assert.Equal(t, alice, forAlice[0].Owner, "the owner has to survive the round trip")

	forBob, err := store.ListAnalyses(ctx, bob, "", 50)
	require.NoError(t, err)
	require.Len(t, forBob, 1)
	assert.Equal(t, his, forBob[0].ID)

	// Naming the other owner's scoped key is not a way in either.
	crossed, err := store.ListAnalyses(ctx, bob, alice+"/"+name, 50)
	require.NoError(t, err)
	assert.Empty(t, crossed)
}

// A client polls a running analysis for its SARIF before there is one. That is
// absence, and a 404 — not a 500.
func TestPostgres_SARIFAbsence(t *testing.T) {
	store := newPostgres(t)
	ctx := context.Background()

	id := unique(t, "an")
	require.NoError(t, store.SaveAnalysis(ctx, analyses.Report{
		ID: id, Project: unique(t, "proj"), Source: "git",
		Status: "running", QueuedAt: storedNow(),
	}))

	doc, found, err := store.ReadSARIF(ctx, id)
	require.NoError(t, err)
	assert.False(t, found, "an analysis that has produced nothing yet has no document")
	assert.Nil(t, doc)

	doc, found, err = store.ReadSARIF(ctx, "nosuchanalysis")
	require.NoError(t, err)
	assert.False(t, found)
	assert.Nil(t, doc)
}

// Writing a document for an id nobody queued would fabricate evidence for an
// analysis that never ran, so it is refused rather than inserted.
func TestPostgres_WriteSARIFForAnUnknownAnalysis(t *testing.T) {
	store := newPostgres(t)

	err := store.WriteSARIF(context.Background(), "nosuchanalysis", []byte(`{}`))

	require.ErrorIs(t, err, analyses.ErrNotFound)
}

// The column is BYTEA precisely so a real SARIF fits: Postgres TOASTs it out of
// line instead of refusing the row.
func TestPostgres_SARIFSurvivesAMultiMegabyteDocument(t *testing.T) {
	store := newPostgres(t)
	ctx := context.Background()

	id := unique(t, "an")
	require.NoError(t, store.SaveAnalysis(ctx, analyses.Report{
		ID: id, Project: unique(t, "proj"), Source: "git",
		Status: "completed", QueuedAt: storedNow(),
	}))

	large := append([]byte(`{"runs":"`), bytes.Repeat([]byte("a"), 3<<20)...)
	large = append(large, []byte(`"}`)...)
	require.NoError(t, store.WriteSARIF(ctx, id, large))

	doc, found, err := store.ReadSARIF(ctx, id)
	require.NoError(t, err)
	require.True(t, found)
	assert.True(t, bytes.Equal(large, doc), "the document must come back byte for byte")
}

// Each project keeps its own history. Sharing one would make every finding of
// the next project look new and every finding of the previous one resolved.
func TestPostgres_ProjectStateIsPerProject(t *testing.T) {
	store := newPostgres(t)
	ctx := context.Background()
	first := unique(t, "proj")
	second := unique(t, "proj")

	require.NoError(t, store.WriteProjectState(ctx, first, []byte(`{"vulns":["a"]}`)))
	require.NoError(t, store.WriteProjectState(ctx, second, []byte(`{"vulns":["b"]}`)))

	got, found, err := store.ReadProjectState(ctx, first)
	require.NoError(t, err)
	require.True(t, found)
	assert.JSONEq(t, `{"vulns":["a"]}`, string(got))

	got, found, err = store.ReadProjectState(ctx, second)
	require.NoError(t, err)
	require.True(t, found)
	assert.JSONEq(t, `{"vulns":["b"]}`, string(got))
}

// The state is rewritten after every run, so a second write replaces the
// document rather than failing on the primary key or appending a second row.
func TestPostgres_ProjectStateIsReplacedNotDuplicated(t *testing.T) {
	store := newPostgres(t)
	ctx := context.Background()
	project := unique(t, "proj")

	require.NoError(t, store.WriteProjectState(ctx, project, []byte(`{"run":1}`)))
	require.NoError(t, store.WriteProjectState(ctx, project, []byte(`{"run":2}`)))

	got, found, err := store.ReadProjectState(ctx, project)
	require.NoError(t, err)
	require.True(t, found)
	assert.JSONEq(t, `{"run":2}`, string(got))
}

// A project analysed for the first time has no history, and that has to be
// distinguishable from a failed read: the first run treats every finding as new.
func TestPostgres_ProjectStateAbsence(t *testing.T) {
	store := newPostgres(t)

	got, found, err := store.ReadProjectState(context.Background(), unique(t, "never"))

	require.NoError(t, err)
	assert.False(t, found)
	assert.Nil(t, got)
}
