package httpapi

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/bootstrap"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

func mkFinding(t *testing.T, file string) finding.Finding {
	t.Helper()

	loc, err := finding.NewLocation(finding.LocationInput{File: file, StartLine: 7}).Get()
	require.NoError(t, err)

	f, err := finding.New(finding.NewFindingInput{
		RuleID:   finding.RuleID("rule-" + file),
		Severity: shared.SeverityHigh,
		Location: loc,
		Message:  finding.Message("sqli in " + file),
		Source:   "semgrep",
		Snippet:  "query := \"SELECT \" + " + file,
	}).Get()
	require.NoError(t, err)

	return f
}

// hammerProject runs `rounds` pairs of concurrent reconciles — one analysis per
// project key, each carrying a finding nothing else reports — and returns how
// many vulnerabilities the shared state ended up holding.
//
// Cumulative on purpose: a reconciliation keeps what this scan did not see,
// marked resolved, rather than dropping it. So every finding ever fed in must
// still be there at the end, and a lost update shows up as a short count.
func hammerProject(t *testing.T, r *Runner, keys [2]string, rounds int) int {
	t.Helper()

	// Built up front: a require inside a goroutine cannot fail a test safely.
	findings := make([][2]finding.Finding, rounds)
	for round := range findings {
		for side := range findings[round] {
			findings[round][side] = mkFinding(t, fmt.Sprintf("round%d/side%d.go", round, side))
		}
	}

	for round := 0; round < rounds; round++ {
		var wg sync.WaitGroup
		for side, key := range keys {
			wg.Add(1)
			go func(id, project string, f finding.Finding) {
				defer wg.Done()

				analysis := Analysis{ID: id, Project: project}
				assert.NoError(t,
					r.reconcile(context.Background(), &analysis, []finding.Finding{f}))
			}(fmt.Sprintf("%d-%d", round, side), key, findings[round][side])
		}
		wg.Wait()
	}

	stored, err := bootstrap.StoreAt(r.store.ProjectStatePath(keys[0])).
		Load(context.Background()).Get()
	require.NoError(t, err)

	return len(stored)
}

// Two analyses of one project reconcile into the same state file, and the
// runner is a pool: nothing stops two workers from being in there at once.
// Both used to load the same history and the later save dropped what the
// earlier one had just recorded, so its findings came back as "new" on the
// next scan and its resolutions were lost. Save is atomic per write, which is
// not the same thing as safe to interleave.
//
// Repeated because the window is a timing one: a single round can pass on a
// broken build.
func TestRunner_ConcurrentAnalysesOfOneProjectKeepBothHistories(t *testing.T) {
	t.Parallel()

	const rounds = 25
	r, _ := newTestRunner(t, newStubRecords())

	got := hammerProject(t, r, [2]string{"acme/api", "acme/api"}, rounds)

	assert.Equal(t, rounds*2, got,
		"every concurrent analysis's findings must survive the other's save")
}

// The lock is keyed by the state path, not by the project name, because the
// name is not what is being protected. Two names the store maps onto one file
// are one history, and keying by name would let them overwrite each other.
func TestRunner_ProjectsThatShareAStateFileShareTheLock(t *testing.T) {
	t.Parallel()

	const rounds = 15
	r, _ := newTestRunner(t, newStubRecords())

	// Distinct keys, one file: sanitizeSegment is not injective, so the
	// trailing punctuation disappears.
	keys := [2]string{"acme/api", "acme/api."}
	require.Equal(t,
		r.store.ProjectStatePath(keys[0]), r.store.ProjectStatePath(keys[1]),
		"this test is only meaningful while these two names share a file")

	got := hammerProject(t, r, keys, rounds)

	assert.Equal(t, rounds*2, got,
		"two names for one state file must not lose each other's findings")
}

// A lock released by one holder must be free for the next, and the table must
// not keep an entry for every project name a client ever invents.
func TestProjectLocks_ReleaseFreesTheEntry(t *testing.T) {
	t.Parallel()

	locks := newProjectLocks()

	release := locks.acquire("one")
	assert.Len(t, locks.entries, 1)
	release()
	assert.Empty(t, locks.entries,
		"project names are caller-chosen; a permanent entry each is a slow leak")

	done := make(chan struct{})
	go func() {
		defer close(done)
		locks.acquire("one")()
	}()
	<-done
}
