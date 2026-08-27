// Package state persists the vulnerability lifecycle between scans.
//
// The format is a single JSON document next to the repository
// (.cortex/state.json by default). That choice is deliberate: it can be
// committed, so the team's triage decisions travel with the code and are
// reviewed like code; or cached by CI; or ignored entirely, in which case
// Cortex behaves like a stateless scanner.
package state

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/domain/vulnerability"
)

// DefaultPath is where the state lives unless configured otherwise.
const DefaultPath = ".cortex/state.json"

// formatVersion guards against silently misreading an older layout. Bump it
// when the document shape changes, and handle the migration explicitly.
const formatVersion = 1

// Store is a JSON-file-backed ports.VulnerabilityStore.
type Store struct {
	path string
}

// New returns a Store writing to path, or to DefaultPath when empty.
func New(path string) *Store {
	if path == "" {
		path = DefaultPath
	}
	return &Store{path: path}
}

// Path is where this store reads and writes.
func (s *Store) Path() string { return s.path }

type document struct {
	Version         int        `json:"version"`
	UpdatedAt       time.Time  `json:"updated_at"`
	Vulnerabilities []vulnJSON `json:"vulnerabilities"`
}

type vulnJSON struct {
	Exact       string      `json:"exact"`
	Content     string      `json:"content,omitempty"`
	Symbol      string      `json:"symbol,omitempty"`
	Status      string      `json:"status"`
	Severity    string      `json:"severity"`
	CWE         string      `json:"cwe,omitempty"`
	RuleID      string      `json:"rule_id"`
	Source      string      `json:"source"`
	Message     string      `json:"message,omitempty"`
	File        string      `json:"file"`
	StartLine   int         `json:"start_line"`
	EndLine     int         `json:"end_line,omitempty"`
	FirstSeen   time.Time   `json:"first_seen"`
	LastSeen    time.Time   `json:"last_seen"`
	ResolvedAt  *time.Time  `json:"resolved_at,omitempty"`
	TimesSeen   int         `json:"times_seen"`
	ReopenCount int         `json:"reopen_count,omitempty"`
	Triage      *triageJSON `json:"triage,omitempty"`
}

type triageJSON struct {
	Status  string     `json:"status"`
	Reason  string     `json:"reason"`
	Author  string     `json:"author,omitempty"`
	At      time.Time  `json:"at"`
	Expires *time.Time `json:"expires,omitempty"`
}

// Load reads the state. A missing file is an empty state, not an error: the
// first scan of a project has nothing to remember.
func (s *Store) Load(_ context.Context) mo.Result[[]vulnerability.Vulnerability] {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return shared.Ok([]vulnerability.Vulnerability{})
		}
		return shared.Err[[]vulnerability.Vulnerability](
			fmt.Errorf("state: read %q: %w", s.path, err))
	}

	vulns, err := decodeState(raw, s.path)
	if err != nil {
		return shared.Err[[]vulnerability.Vulnerability](err)
	}
	return shared.Ok(vulns)
}

// decodeState turns a stored document into aggregates. origin only appears in
// error messages — a path for the file store, a URL for the remote one — so
// both backends read the same bytes and report failures the same way.
func decodeState(raw []byte, origin string) ([]vulnerability.Vulnerability, error) {
	var doc document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("state: parse %s: %w", origin, err)
	}

	// An empty document with no version is how a backend says "nothing stored
	// yet"; only a populated document has to declare a format it was written in.
	unwritten := doc.Version == 0 && len(doc.Vulnerabilities) == 0
	if !unwritten && doc.Version != formatVersion {
		return nil, fmt.Errorf(
			"state: %s has format version %d, this build understands %d",
			origin, doc.Version, formatVersion)
	}

	out := make([]vulnerability.Vulnerability, 0, len(doc.Vulnerabilities))
	for _, item := range doc.Vulnerabilities {
		v, err := restore(item)
		if err != nil {
			return nil, fmt.Errorf("state: entry %s: %w", item.Exact, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// encodeState serialises the aggregates into the stored document shape.
func encodeState(vulns []vulnerability.Vulnerability) ([]byte, error) {
	doc := document{
		Version:         formatVersion,
		UpdatedAt:       time.Now().UTC(),
		Vulnerabilities: make([]vulnJSON, 0, len(vulns)),
	}
	for _, v := range vulns {
		doc.Vulnerabilities = append(doc.Vulnerabilities, marshal(v))
	}

	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("state: encode: %w", err)
	}
	return append(encoded, '\n'), nil
}

// Save writes the state atomically: a temp file in the same directory followed
// by a rename, so an interrupted CI job cannot leave a half-written document
// that the next run refuses to parse.
func (s *Store) Save(
	_ context.Context, vulns []vulnerability.Vulnerability,
) mo.Result[int] {
	encoded, err := encodeState(vulns)
	if err != nil {
		return shared.Err[int](err)
	}

	dir := filepath.Dir(s.path)
	if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
		return shared.Err[int](fmt.Errorf("state: create %q: %w", dir, mkErr))
	}

	tmp, err := os.CreateTemp(dir, ".state-*.json")
	if err != nil {
		return shared.Err[int](fmt.Errorf("state: temp file: %w", err))
	}
	tmpName := tmp.Name()

	if _, writeErr := tmp.Write(encoded); writeErr != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return shared.Err[int](fmt.Errorf("state: write: %w", writeErr))
	}
	if closeErr := tmp.Close(); closeErr != nil {
		_ = os.Remove(tmpName)
		return shared.Err[int](fmt.Errorf("state: close: %w", closeErr))
	}
	if renameErr := os.Rename(tmpName, s.path); renameErr != nil {
		_ = os.Remove(tmpName)
		return shared.Err[int](fmt.Errorf("state: rename into %q: %w", s.path, renameErr))
	}

	return shared.Ok(len(vulns))
}

func marshal(v vulnerability.Vulnerability) vulnJSON {
	item := vulnJSON{
		Exact:       v.Identity().Exact.String(),
		Content:     v.Identity().Content.String(),
		Symbol:      v.Identity().Symbol.String(),
		Status:      v.Status().String(),
		Severity:    v.Severity().String(),
		RuleID:      v.RuleID().String(),
		Source:      v.Source().String(),
		Message:     v.Message().String(),
		File:        v.Location().File(),
		StartLine:   v.Location().StartLine(),
		EndLine:     v.Location().EndLine(),
		FirstSeen:   v.FirstSeen().UTC(),
		LastSeen:    v.LastSeen().UTC(),
		TimesSeen:   v.TimesSeen(),
		ReopenCount: v.ReopenCount(),
	}
	if cwe, ok := v.CWE().Get(); ok {
		item.CWE = cwe.String()
	}
	if at, ok := v.ResolvedAt().Get(); ok {
		utc := at.UTC()
		item.ResolvedAt = &utc
	}
	if t, ok := v.TriageDecision().Get(); ok {
		decision := &triageJSON{
			Status: t.Status().String(),
			Reason: t.Reason(),
			Author: t.Author(),
			At:     t.At().UTC(),
		}
		if expires, hasExpiry := t.Expires().Get(); hasExpiry {
			utc := expires.UTC()
			decision.Expires = &utc
		}
		item.Triage = decision
	}
	return item
}

func restore(item vulnJSON) (vulnerability.Vulnerability, error) {
	status, err := vulnerability.ParseStatus(item.Status).Get()
	if err != nil {
		return vulnerability.Vulnerability{}, err
	}

	loc, err := finding.NewLocation(finding.LocationInput{
		File:      item.File,
		StartLine: item.StartLine,
		EndLine:   item.EndLine,
	}).Get()
	if err != nil {
		return vulnerability.Vulnerability{}, err
	}

	in := vulnerability.RestoreInput{
		Identity: vulnerability.Identity{
			Exact:   finding.Fingerprint(item.Exact),
			Content: finding.Fingerprint(item.Content),
			Symbol:  finding.Fingerprint(item.Symbol),
		},
		Status:      status,
		Severity:    shared.ParseSeverity(item.Severity),
		RuleID:      finding.RuleID(item.RuleID),
		Source:      finding.ScannerName(item.Source),
		Message:     finding.Message(item.Message),
		Location:    loc,
		FirstSeen:   item.FirstSeen,
		LastSeen:    item.LastSeen,
		TimesSeen:   item.TimesSeen,
		ReopenCount: item.ReopenCount,
	}

	if item.CWE != "" {
		cwe, cweErr := finding.NewCWE(item.CWE).Get()
		if cweErr != nil {
			return vulnerability.Vulnerability{}, cweErr
		}
		in.CWE = shared.Some(cwe)
	}
	if item.ResolvedAt != nil {
		in.ResolvedAt = shared.Some(*item.ResolvedAt)
	}
	if item.Triage != nil {
		triage, triageErr := restoreTriage(*item.Triage)
		if triageErr != nil {
			return vulnerability.Vulnerability{}, triageErr
		}
		in.Triage = shared.Some(triage)
	}

	return vulnerability.Restore(in), nil
}

func restoreTriage(item triageJSON) (vulnerability.Triage, error) {
	status, err := vulnerability.ParseStatus(item.Status).Get()
	if err != nil {
		return vulnerability.Triage{}, err
	}

	expires := mo.None[time.Time]()
	if item.Expires != nil {
		expires = shared.Some(*item.Expires)
	}

	return vulnerability.NewTriage(status, item.Reason, item.Author, item.At, expires).Get()
}
