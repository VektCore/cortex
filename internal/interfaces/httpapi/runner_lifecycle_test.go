package httpapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/infrastructure/config"
	"github.com/vektcore/cortex/internal/infrastructure/logging"
)

// stubRecords is an in-memory analysisRecords whose load can be made to fail.
//
// The embedded interface is deliberately left nil: only the methods these
// tests exercise are implemented, so the rest of the interface can keep
// changing without dragging them along. A call to anything else is a bug in
// the test and says so loudly.
type stubRecords struct {
	analysisRecords

	mu      sync.Mutex
	saved   map[string]Analysis
	loadErr error
}

func newStubRecords() *stubRecords {
	return &stubRecords{saved: make(map[string]Analysis)}
}

func (s *stubRecords) SaveAnalysis(_ context.Context, a Analysis) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.saved[a.ID] = a
	return nil
}

func (s *stubRecords) LoadAnalysis(_ context.Context, id string) (Analysis, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.loadErr != nil {
		return Analysis{}, false, s.loadErr
	}
	a, ok := s.saved[id]
	return a, ok, nil
}

func (s *stubRecords) failLoads(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.loadErr = err
}

func (s *stubRecords) get(t *testing.T, id string) Analysis {
	t.Helper()

	a, found, err := s.LoadAnalysis(context.Background(), id)
	require.NoError(t, err)
	require.True(t, found, "no record for %s", id)
	return a
}

// newTestRunner builds a runner with no goroutines behind it: no worker races
// the test for a queued id and no sweeper removes a file mid-assertion. The
// tests drive run, Stop and sweepOnce themselves.
func newTestRunner(t *testing.T, records analysisRecords) (*Runner, *Store) {
	t.Helper()

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	r := newRunner(&config.Config{}, store, records, logging.NewNop())
	t.Cleanup(r.Stop)

	return r, store
}

func writeArchive(t *testing.T, store *Store, id string, size int) {
	t.Helper()

	f, err := store.CreateArchive(id)
	require.NoError(t, err)
	_, err = f.Write(make([]byte, size))
	require.NoError(t, err)
	require.NoError(t, f.Close())
}

// backdate pushes something past the grace, so the sweeper stops treating it
// as work that might still be live.
func backdate(t *testing.T, path string) {
	t.Helper()

	when := time.Now().Add(-2 * leftoverGrace)
	require.NoError(t, os.Chtimes(path, when, when))
}

// An analysis whose record cannot be read still owns the archive its client
// uploaded. run() used to return before registering the cleanup, so a database
// blip — or a record that never got written — left that source in archives/
// for the life of the volume.
func TestRunner_DropsTheArchiveWhenTheRecordCannotBeLoaded(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*stubRecords){
		"the store cannot answer": func(s *stubRecords) { s.failLoads(errors.New("database is down")) },
		"the record is absent":    func(*stubRecords) {},
	}

	for name, arrange := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			records := newStubRecords()
			arrange(records)
			r, store := newTestRunner(t, records)

			const id = "no-record"
			writeArchive(t, store, id, 128)
			require.True(t, r.Enqueue(id))

			r.run(id)

			assert.NoFileExists(t, store.ArchivePath(id),
				"the client's source must not outlive an analysis that never started")
			assert.False(t, r.backlog.holds(id),
				"an analysis that is over must not keep holding its share of the disk budget")
		})
	}
}

// Stop used to discard whatever was still in the queue. Those analyses stayed
// "queued" in the store with no worker left to run them — a client polling one
// would wait forever — and their uploaded source stayed on disk.
func TestRunner_ShutdownFailsQueuedWorkAndDropsItsArchive(t *testing.T) {
	t.Parallel()

	records := newStubRecords()
	r, store := newTestRunner(t, records)

	const id = "never-started"
	require.NoError(t, records.SaveAnalysis(context.Background(), Analysis{
		ID: id, Project: "acme/api", Source: SourceUpload,
		Status: StatusQueued, QueuedAt: time.Now().UTC(),
	}))
	writeArchive(t, store, id, 64)
	require.True(t, r.Enqueue(id))

	r.Stop()

	got := records.get(t, id)
	assert.Equal(t, StatusFailed, got.Status,
		"an analysis nothing will ever run must not be left saying it is queued")
	assert.Contains(t, got.Error, "shut down")
	assert.NotNil(t, got.FinishedAt, "a client polling this needs to see it end")
	assert.NoFileExists(t, store.ArchivePath(id),
		"the uploaded source of an analysis that never ran must not survive the shutdown")
}

// A terminal record is not rewritten by the shutdown path: an analysis that
// completed a second before Stop must keep its result, not be reported as
// interrupted.
func TestRunner_ShutdownLeavesFinishedAnalysesAlone(t *testing.T) {
	t.Parallel()

	records := newStubRecords()
	r, _ := newTestRunner(t, records)

	const id = "already-done"
	require.NoError(t, records.SaveAnalysis(context.Background(), Analysis{
		ID: id, Project: "acme/api", Status: StatusCompleted, Gate: "passed",
	}))
	require.True(t, r.Enqueue(id))

	r.Stop()

	got := records.get(t, id)
	assert.Equal(t, StatusCompleted, got.Status)
	assert.Empty(t, got.Error)
}

// The sweeper is the backstop for the exits the process is not given. A
// SIGKILL or an OOM kill mid-analysis leaves the client's source in archives/
// and its expanded tree in work/, and before this nothing ever looked at
// either again.
func TestRunner_SweepReclaimsWhatAnEarlierProcessLeftBehind(t *testing.T) {
	t.Parallel()

	records := newStubRecords()
	r, store := newTestRunner(t, records)
	ctx := context.Background()

	// Killed while running: the record still claims to be running, but it was
	// started longer ago than an analysis is allowed to last.
	longAgo := time.Now().Add(-2 * leftoverGrace).UTC()
	require.NoError(t, records.SaveAnalysis(ctx, Analysis{
		ID: "killed", Project: "acme/api", Source: SourceUpload,
		Status: StatusRunning, StartedAt: &longAgo,
	}))
	writeArchive(t, store, "killed", 32)
	backdate(t, store.ArchivePath("killed"))

	// Upload that never got a record — the handler died between writing the
	// file and saving the analysis.
	writeArchive(t, store, "orphan", 32)
	backdate(t, store.ArchivePath("orphan"))

	// An upload still streaming in: no record yet, but the file is being
	// written to right now.
	writeArchive(t, store, "arriving", 32)

	// Queued behind a deep backlog on this very process. Old, but ours.
	writeArchive(t, store, "waiting", 32)
	backdate(t, store.ArchivePath("waiting"))
	require.True(t, r.Enqueue("waiting"))

	// Genuinely running here and now.
	justStarted := time.Now().UTC()
	require.NoError(t, records.SaveAnalysis(ctx, Analysis{
		ID: "in-flight", Project: "acme/api", Source: SourceUpload,
		Status: StatusRunning, StartedAt: &justStarted,
	}))
	writeArchive(t, store, "in-flight", 32)
	backdate(t, store.ArchivePath("in-flight"))

	stale := filepath.Join(store.WorkDir(), "cortex-src-stale")
	require.NoError(t, os.MkdirAll(filepath.Join(stale, "pkg"), 0o750))
	backdate(t, stale)

	live := filepath.Join(store.WorkDir(), "cortex-src-live")
	require.NoError(t, os.MkdirAll(live, 0o750))

	r.sweepOnce()

	assert.NoFileExists(t, store.ArchivePath("killed"),
		"source left behind by a killed analysis must not stay on disk")
	assert.Equal(t, StatusFailed, records.get(t, "killed").Status,
		"an analysis whose process is gone must stop claiming to be running")
	assert.NoFileExists(t, store.ArchivePath("orphan"),
		"an upload no record will ever claim is exactly what the sweeper is for")

	assert.FileExists(t, store.ArchivePath("arriving"),
		"an upload still being written is not debris")
	assert.FileExists(t, store.ArchivePath("waiting"),
		"an archive this process still means to analyse must survive the sweep")
	assert.FileExists(t, store.ArchivePath("in-flight"),
		"deleting the source of a running analysis would break it")

	assert.NoDirExists(t, stale, "an expanded source tree outlives nothing")
	assert.DirExists(t, live, "a tree younger than one analysis may still be in use")
}

// The queue bounds analyses, not bytes: 256 slots against a 256 MiB upload
// limit admits some 64 GiB of client source ahead of two workers, on a host
// that is also running the databases. Refusal reaches the client as the same
// 503 a full queue produces, and the handler deletes the archive it wrote.
func TestRunner_RefusesWorkOnceTheQueuedArchivesFillTheBudget(t *testing.T) {
	t.Parallel()

	r, store := newTestRunner(t, newStubRecords())
	r.backlog = newArchiveBacklog(1000)

	writeArchive(t, store, "first", 600)
	writeArchive(t, store, "second", 600)

	require.True(t, r.Enqueue("first"))
	assert.False(t, r.Enqueue("second"),
		"two archives that together exceed the budget must not both be admitted")
	assert.False(t, r.backlog.holds("second"),
		"a refused analysis must not be charged for disk it was never allowed to use")

	// A git analysis holds no archive, so the disk budget has no opinion on it.
	assert.True(t, r.Enqueue("cloned"))

	// And once the first one is done with, the budget is free again.
	r.backlog.release("first")
	assert.True(t, r.Enqueue("second"))
}
