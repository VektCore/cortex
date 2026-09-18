package httpapi

import "sync"

// defaultArchiveBacklogBytes caps the uploaded source that may sit on disk
// waiting for a worker.
//
// The queue counts analyses, not bytes: 256 slots against an upload limit of
// 256 MiB admits some 64 GiB of client source ahead of two workers, on a host
// that is also running six PostgreSQL databases. The slot count is the wrong
// bound for the resource that actually runs out, and nothing else in the
// service knows both how deep the backlog is and how big each archive is —
// the upload handler sees one request, the operator's disk quota sees the
// whole volume long after the damage.
//
// Refusing here costs nothing the client cannot handle: Enqueue's false is
// already the "queue is full" path, which answers 503 and deletes the archive
// it had just written, so a refused upload leaves nothing behind.
const defaultArchiveBacklogBytes int64 = 4 << 30

// archiveBacklog tracks the disk charged to the analyses this process intends
// to run: charged when the analysis is queued, released when the worker is
// done with it or when shutdown gives up on it.
//
// It doubles as the answer to "is this archive still somebody's?", which is
// what keeps the sweeper from deleting source out from under a queued run.
type archiveBacklog struct {
	mu      sync.Mutex
	budget  int64
	used    int64
	charged map[string]int64
}

func newArchiveBacklog(budget int64) *archiveBacklog {
	return &archiveBacklog{budget: budget, charged: make(map[string]int64)}
}

// reserve charges size to id, reporting false when that would take the backlog
// over budget. Nothing is charged on a refusal.
//
// An archive larger than the entire budget is admitted when the backlog is
// empty. Refusing it would reject it forever however long the client waited,
// and its size was already accepted by server.upload.max_archive_bytes.
func (b *archiveBacklog) reserve(id string, size int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.charged[id]; exists {
		return true
	}
	if b.used > 0 && b.used+size > b.budget {
		return false
	}

	b.charged[id] = size
	b.used += size
	return true
}

// release drops the charge. An unknown id is ignored: every exit path calls
// this, including ones that never reserved anything.
func (b *archiveBacklog) release(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	size, ok := b.charged[id]
	if !ok {
		return
	}
	delete(b.charged, id)
	b.used -= size
}

// holds reports whether this process still intends to run id.
func (b *archiveBacklog) holds(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	_, ok := b.charged[id]
	return ok
}
