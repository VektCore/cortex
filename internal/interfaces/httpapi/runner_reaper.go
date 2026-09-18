package httpapi

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vektcore/cortex/internal/application/ports"
)

const (
	// sweepInterval is how often the runner goes looking for leftovers. The
	// sweep at startup is the important one — that is when a killed process's
	// debris is found — but a server that stays up for months would otherwise
	// never look again.
	sweepInterval = 30 * time.Minute

	// leftoverGrace is how old something must be before the sweeper will call
	// it dead. It is deliberately longer than analysisTimeout, so nothing
	// belonging to a live analysis can reach it: an extraction directory is
	// created at the start of a run that cannot outlast that timeout, and an
	// archive a client is still streaming in has its mtime moving.
	leftoverGrace = analysisTimeout + 15*time.Minute

	// archiveSuffix is the extension Store.ArchivePath writes.
	archiveSuffix = ".zip"
)

// sweep reclaims what earlier runs left behind, and keeps doing it.
func (r *Runner) sweep() {
	defer r.wg.Done()

	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for {
		r.sweepOnce()

		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sweepOnce drops uploaded archives nothing will ever claim and extraction
// directories nobody is reading.
//
// It exists because the process is not always given the chance to clean up
// after itself. A SIGKILL, an OOM kill or a panic mid-analysis leaves the
// client's source in archives/ and its expanded tree in work/, and without a
// sweep nothing would ever look at either again — which is how a data
// directory quietly becomes a copy of every repository the service has seen.
func (r *Runner) sweepOnce() {
	archives := r.sweepArchives()
	trees := r.sweepWorkDirs()
	if archives+trees == 0 {
		return
	}

	r.logger.Info("reclaimed leftovers from an earlier run",
		ports.F("archives", fmt.Sprint(archives)),
		ports.F("work_dirs", fmt.Sprint(trees)))
}

// sweepArchives removes the uploads no analysis is waiting on, and fails the
// records that were left mid-flight so a client polling one stops being told
// it is about to run.
func (r *Runner) sweepArchives() int {
	dir := r.store.ArchiveDir()

	entries, err := os.ReadDir(dir)
	if err != nil {
		r.logger.Warn("could not list the archive directory",
			ports.F("dir", dir), ports.F("error", err.Error()))
		return 0
	}

	swept := 0
	for _, entry := range entries {
		if r.ctx.Err() != nil {
			return swept
		}
		id, ok := archiveID(entry)
		if !ok || !r.orphaned(id, entry) {
			continue
		}
		r.abandon(id, "interrupted: the server stopped before this analysis finished")
		swept++
	}
	return swept
}

// orphaned decides whether an archive still belongs to something that could
// run. It errs towards keeping: a wrong answer here deletes a client's source.
func (r *Runner) orphaned(id string, entry os.DirEntry) bool {
	// Queued or in flight on this process. The definitive answer, and the one
	// that keeps a deep backlog — where an archive can wait hours for a worker
	// — from being mistaken for debris.
	if r.backlog.holds(id) {
		return false
	}

	modTime, known := entryModTime(entry)
	if !known {
		return false
	}
	// A recent write means the file may be an upload still streaming in, whose
	// record the handler has not saved yet.
	if time.Since(modTime) < leftoverGrace {
		return false
	}

	analysis, found, err := r.records.LoadAnalysis(context.Background(), id)
	if err != nil {
		// A store that cannot answer is not evidence that nobody wants this.
		return false
	}
	if !found {
		return true
	}

	// Anything that is not a run started recently is finished, or was left
	// queued by a process that no longer exists: the queue lives in memory and
	// does not survive a restart.
	return !startedRecently(analysis)
}

func startedRecently(a Analysis) bool {
	return a.Status == StatusRunning &&
		a.StartedAt != nil &&
		time.Since(*a.StartedAt) < leftoverGrace
}

// sweepWorkDirs removes expanded source trees whose analysis is long gone.
//
// Everything under work/ is an extraction, so age is the whole test — and an
// extraction that belongs to a live analysis cannot be older than the timeout
// that analysis runs under.
func (r *Runner) sweepWorkDirs() int {
	dir := r.store.WorkDir()

	entries, err := os.ReadDir(dir)
	if err != nil {
		r.logger.Warn("could not list the work directory",
			ports.F("dir", dir), ports.F("error", err.Error()))
		return 0
	}

	swept := 0
	for _, entry := range entries {
		if r.ctx.Err() != nil {
			return swept
		}
		modTime, known := entryModTime(entry)
		if !known || time.Since(modTime) < leftoverGrace {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		if removeErr := os.RemoveAll(path); removeErr != nil {
			r.logger.Warn("could not remove an abandoned source tree",
				ports.F("path", path), ports.F("error", removeErr.Error()))
			continue
		}
		swept++
	}
	return swept
}

// archiveID recovers the analysis id from a file in archives/. Anything that is
// not an archive is left alone.
func archiveID(entry os.DirEntry) (string, bool) {
	name := entry.Name()
	if entry.IsDir() || !strings.HasSuffix(name, archiveSuffix) {
		return "", false
	}
	return strings.TrimSuffix(name, archiveSuffix), true
}

// entryModTime reports when the entry was last written, and false when that
// cannot be told — something that vanished between the listing and the stat is
// already gone, which is what the sweeper wanted anyway.
func entryModTime(entry os.DirEntry) (time.Time, bool) {
	info, err := entry.Info()
	if err != nil {
		return time.Time{}, false
	}
	return info.ModTime(), true
}
