package httpapi

import "sync"

// projectLocks serialises the analyses that share one project's state file.
//
// The runner is a worker pool, so two analyses of the same project can be in
// flight at once, and reconciliation is load → merge → save over a single JSON
// document. Both would read the same history and the later save would drop
// whatever the earlier one recorded: a finding first seen by one of them comes
// back as new on the next scan, and a resolution is simply lost.
// state.Store.Save writes temp-then-rename, which prevents a half-written file
// — it does nothing about a lost update.
//
// # What this does not cover
//
// It is an in-process lock. Two server instances behind one database each hold
// their own lock and neither sees the other. Today that is not a live bug,
// because the state files live under each instance's own data directory (and
// the queue lives in its memory), so two instances do not reconcile the same
// file at all — they keep two divergent histories instead, which is a separate
// problem and not one the runner can fix. The moment that state moves behind
// something shared, this lock stops being enough, and the fix belongs where the
// document is written: a compare-and-swap or version check in
// infrastructure/state, or an advisory lock in Postgres. Not here.
//
// Serialising the whole queue by project was the alternative: it needs no lock
// at all, but it makes one slow project's second analysis wait behind the first
// for the full analysis — up to 45 minutes — to protect a file write measured
// in milliseconds. Locking only the reconcile step keeps the scans parallel.
type projectLocks struct {
	mu      sync.Mutex
	entries map[string]*projectLock
}

// projectLock is one project's mutex and how many analyses want it. The count
// exists so the map does not keep an entry for every project name a client
// ever invents: project names are caller-chosen.
type projectLock struct {
	mu      sync.Mutex
	waiting int
}

func newProjectLocks() *projectLocks {
	return &projectLocks{entries: make(map[string]*projectLock)}
}

// acquire blocks until key is free and returns the release. Call it once.
func (p *projectLocks) acquire(key string) func() {
	p.mu.Lock()
	entry, ok := p.entries[key]
	if !ok {
		entry = &projectLock{}
		p.entries[key] = entry
	}
	entry.waiting++
	p.mu.Unlock()

	entry.mu.Lock()

	return func() {
		entry.mu.Unlock()

		p.mu.Lock()
		defer p.mu.Unlock()

		entry.waiting--
		if entry.waiting == 0 {
			delete(p.entries, key)
		}
	}
}
