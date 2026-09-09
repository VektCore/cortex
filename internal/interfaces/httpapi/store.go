package httpapi

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Status values for an analysis.
const (
	StatusQueued    = "queued"
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
)

// Where the analysed code came from.
const (
	// SourceGit is a repository the server clones itself.
	SourceGit = "git"
	// SourceUpload is an archive the client's pipeline posted, which is how a
	// client gets analysed without granting the server access to its code.
	SourceUpload = "upload"
)

// Analysis is one request to analyse a repository, and its outcome.
//
// It is deliberately flat and JSON-shaped: this is what a client polls, so its
// field names are a public contract.
type Analysis struct {
	ID      string `json:"id"`
	Project string `json:"project"`
	// Source says where the code came from: SourceGit, which the server clones,
	// or SourceUpload, which the client's pipeline sent as an archive. It
	// decides what the runner does and what the record can be trusted to say —
	// an upload has no git metadata of its own.
	Source string `json:"source"`
	// Repository is the git URL for SourceGit. For SourceUpload it is optional
	// metadata the pipeline may send so results can still be attributed.
	Repository string `json:"repository,omitempty"`
	Ref        string `json:"ref,omitempty"`
	// Commit is the revision actually analysed, which is what GitHub needs to
	// attach alerts and a status to the right place.
	Commit     string         `json:"commit,omitempty"`
	Status     string         `json:"status"`
	Gate       string         `json:"gate,omitempty"` // passed | failed
	Findings   int            `json:"findings"`
	BySeverity map[string]int `json:"by_severity,omitempty"`
	// NewFindings is how many of them the project had never seen. It is the
	// number a returning client actually reads.
	NewFindings int `json:"new_findings"`
	Reopened    int `json:"reopened"`
	Resolved    int `json:"resolved"`
	// ScannersRan and ScannerErrors together say how much of the scan actually
	// happened. A run where four of five tools failed must not read as clean.
	ScannersRan   int               `json:"scanners_ran"`
	ScannerErrors map[string]string `json:"scanner_errors,omitempty"`
	// KnownBefore is how many vulnerabilities the project already had.
	KnownBefore int        `json:"known_before"`
	RequestedBy string     `json:"requested_by,omitempty"`
	Error       string     `json:"error,omitempty"`
	QueuedAt    time.Time  `json:"queued_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
}

// Store persists analyses, their SARIF and each project's state directory.
//
// One JSON file per analysis under a directory the operator mounts. Not a
// database: the point is that a single binary plus a volume is a deployable
// service. Swapping this for Postgres means replacing this type only.
type Store struct {
	root string
	mu   sync.RWMutex
}

// NewStore prepares the directory layout under root.
func NewStore(root string) (*Store, error) {
	for _, dir := range []string{"analyses", "projects", "scans", "archives", "work"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
			return nil, fmt.Errorf("data dir %q: %w", filepath.Join(root, dir), err)
		}
	}
	return &Store{root: root}, nil
}

func (s *Store) analysisPath(id string) string {
	return filepath.Join(s.root, "analyses", id+".json")
}

// SarifPath is where an analysis's canonical SARIF lives.
func (s *Store) SarifPath(id string) string {
	return filepath.Join(s.root, "analyses", id+".sarif")
}

// ScanPath is where an ingested SARIF (posted by a client's own CI) lives.
func (s *Store) ScanPath(id string) string {
	return filepath.Join(s.root, "scans", id+".sarif")
}

// WorkDir is where uploaded archives are expanded. It lives under the data
// directory, not /tmp: in a container /tmp is often small or memory-backed,
// and a source tree of a few hundred megabytes has to land somewhere real.
func (s *Store) WorkDir() string {
	return filepath.Join(s.root, "work")
}

// ArchivePath is where an uploaded source archive is parked between the
// request that delivered it and the worker that expands it. It holds a
// client's source, so the runner deletes it as soon as the analysis ends.
func (s *Store) ArchivePath(id string) string {
	return filepath.Join(s.root, "archives", id+".zip")
}

// CreateArchive opens the archive file for streaming. The upload is written
// straight to disk: buffering a quarter-gigabyte POST in memory is how one
// client takes the server down for the others.
func (s *Store) CreateArchive(id string) (*os.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.OpenFile(s.ArchivePath(id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create archive for %s: %w", id, err)
	}
	return f, nil
}

// RemoveArchive deletes an uploaded archive. Absence is not an error: the
// caller removes it on every exit path, including ones where it never landed.
func (s *Store) RemoveArchive(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.Remove(s.ArchivePath(id)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove archive for %s: %w", id, err)
	}
	return nil
}

// ProjectStatePath is the vulnerability state file for a project. Each project
// gets its own: sharing one would make every finding of the next project look
// new and every finding of the previous one resolved.
func (s *Store) ProjectStatePath(project string) string {
	return filepath.Join(s.root, "projects", sanitizeSegment(project)+".state.json")
}

// SaveAnalysis writes the record, replacing any previous version.
func (s *Store) SaveAnalysis(a Analysis) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	encoded, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return fmt.Errorf("encode analysis: %w", err)
	}
	return os.WriteFile(s.analysisPath(a.ID), append(encoded, '\n'), 0o600)
}

// LoadAnalysis returns one record. A missing id is reported as not found so the
// handler can answer 404 rather than 500.
func (s *Store) LoadAnalysis(id string) (Analysis, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	raw, err := os.ReadFile(s.analysisPath(id))
	if os.IsNotExist(err) {
		return Analysis{}, false, nil
	}
	if err != nil {
		return Analysis{}, false, fmt.Errorf("read analysis %s: %w", id, err)
	}

	var a Analysis
	if unmarshalErr := json.Unmarshal(raw, &a); unmarshalErr != nil {
		return Analysis{}, false, fmt.Errorf("parse analysis %s: %w", id, unmarshalErr)
	}
	return a, true, nil
}

// ListAnalyses returns the most recent records, newest first, optionally
// filtered by project.
func (s *Store) ListAnalyses(project string, limit int) ([]Analysis, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(filepath.Join(s.root, "analyses"))
	if err != nil {
		return nil, fmt.Errorf("list analyses: %w", err)
	}

	out := make([]Analysis, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(s.root, "analyses", entry.Name()))
		if readErr != nil {
			continue // a half-written record must not break the listing
		}
		var a Analysis
		if json.Unmarshal(raw, &a) != nil {
			continue
		}
		if project != "" && a.Project != project {
			continue
		}
		out = append(out, a)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].QueuedAt.After(out[j].QueuedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// WriteBlob stores a SARIF document at path.
func (s *Store) WriteBlob(path string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.WriteFile(path, data, 0o600)
}

// ReadBlob returns a stored document, reporting absence separately.
func (s *Store) ReadBlob(path string) ([]byte, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

// sanitizeSegment keeps a client-supplied name from escaping the data
// directory: a project called "../../etc" must not become a path.
func sanitizeSegment(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), ".-")
	if out == "" {
		return "default"
	}
	return out
}
