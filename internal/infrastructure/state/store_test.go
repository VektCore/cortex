package state_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/domain/vulnerability"
	"github.com/vektcore/cortex/internal/infrastructure/state"
)

func mkVuln(t *testing.T, file, symbol string, now time.Time) vulnerability.Vulnerability {
	t.Helper()

	loc, err := finding.NewLocation(finding.LocationInput{File: file, StartLine: 12}).Get()
	require.NoError(t, err)

	cwe, err := finding.NewCWE("CWE-89").Get()
	require.NoError(t, err)

	f, err := finding.New(finding.NewFindingInput{
		RuleID:     "B608",
		Severity:   shared.SeverityCritical,
		Location:   loc,
		Message:    "sqli",
		Source:     "bandit",
		Snippet:    "query = 'SELECT '+x",
		CWE:        shared.Some(cwe),
		SymbolName: symbol,
	}).Get()
	require.NoError(t, err)

	return vulnerability.NewFromFinding(f, now)
}

func TestStore_MissingFileIsAnEmptyState(t *testing.T) {
	t.Parallel()

	store := state.New(filepath.Join(t.TempDir(), "nested", "state.json"))

	loaded, err := store.Load(context.Background()).Get()
	require.NoError(t, err, "a project's first scan has nothing to remember and must not fail")
	assert.Empty(t, loaded)
}

func TestStore_RoundTripPreservesIdentityAndTriage(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	store := state.New(filepath.Join(t.TempDir(), "state.json"))

	original := mkVuln(t, "app/db.py", "get_user", now)
	deadline := now.Add(30 * 24 * time.Hour)
	decision, err := vulnerability.NewTriage(
		vulnerability.StatusAcceptedRisk, "migrating in Q4", "daniel", now,
		shared.Some(deadline),
	).Get()
	require.NoError(t, err)
	original = original.Triage(decision)

	saved, err := store.Save(context.Background(), []vulnerability.Vulnerability{original}).Get()
	require.NoError(t, err)
	assert.Equal(t, 1, saved)

	loaded, err := store.Load(context.Background()).Get()
	require.NoError(t, err)
	require.Len(t, loaded, 1)

	got := loaded[0]
	assert.Equal(t, original.Identity(), got.Identity(),
		"all three fingerprints must survive storage, or matching degrades silently")
	assert.Equal(t, vulnerability.StatusAcceptedRisk, got.Status())
	assert.Equal(t, shared.SeverityCritical, got.Severity())
	assert.Equal(t, "app/db.py", got.Location().File())
	assert.Equal(t, original.FirstSeen().UTC(), got.FirstSeen())

	triage, ok := got.TriageDecision().Get()
	require.True(t, ok)
	assert.Equal(t, "migrating in Q4", triage.Reason())
	assert.Equal(t, "daniel", triage.Author())
	expires, hasExpiry := triage.Expires().Get()
	require.True(t, hasExpiry, "an accepted risk without its deadline would never expire")
	assert.Equal(t, deadline.UTC(), expires)

	cwe, hasCWE := got.CWE().Get()
	require.True(t, hasCWE)
	assert.Equal(t, "CWE-89", cwe.String())
}

func TestStore_SaveIsAtomicAndOverwrites(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "state.json")
	store := state.New(path)
	ctx := context.Background()

	first := []vulnerability.Vulnerability{
		mkVuln(t, "a.py", "one", now),
		mkVuln(t, "b.py", "two", now),
	}
	_, err := store.Save(ctx, first).Get()
	require.NoError(t, err)

	// The state is replaced, not appended to: it is the current truth.
	_, err = store.Save(ctx, first[:1]).Get()
	require.NoError(t, err)

	loaded, err := store.Load(ctx).Get()
	require.NoError(t, err)
	assert.Len(t, loaded, 1)

	// No temp file left behind.
	leftovers, globErr := filepath.Glob(filepath.Join(filepath.Dir(path), ".state-*"))
	require.NoError(t, globErr)
	assert.Empty(t, leftovers)
}

func TestStore_RefusesAnUnknownFormatVersion(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	require.NoError(t, writeFile(path, `{"version": 99, "vulnerabilities": []}`))

	_, err := state.New(path).Load(context.Background()).Get()
	require.Error(t, err, "a future format must fail loudly, not be read as an empty state")
	assert.Contains(t, err.Error(), "format version")
}

func TestStore_DefaultPath(t *testing.T) {
	t.Parallel()
	assert.Equal(t, state.DefaultPath, state.New("").Path())
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
