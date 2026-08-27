package scan

import (
	"strings"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/domain/shared"
)

// ID identifies a Scan instance. Generation is the application layer's
// responsibility (typically a UUID via an injected IDGenerator port).
type ID string

func (id ID) String() string { return string(id) }
func (id ID) Empty() bool    { return id == "" }

// NewID validates and constructs an ID.
func NewID(raw string) mo.Result[ID] {
	s := strings.TrimSpace(raw)
	if s == "" {
		return shared.Err[ID](shared.NewDomainError("SCAN_ID_EMPTY", "scan id is empty"))
	}
	return shared.Ok(ID(s))
}

// Revision describes the git revision under analysis.
type Revision struct {
	commit string
	branch string
}

// NewRevision validates and constructs a Revision. branch may be empty
// when scanning a detached HEAD or a tarball.
func NewRevision(commit, branch string) mo.Result[Revision] {
	c := strings.TrimSpace(commit)
	if c == "" {
		return shared.Err[Revision](shared.NewDomainError(
			"REVISION_NO_COMMIT", "commit hash is required"))
	}
	return shared.Ok(Revision{commit: c, branch: strings.TrimSpace(branch)})
}

func (r Revision) Commit() string { return r.commit }
func (r Revision) Branch() string { return r.branch }

// UnknownRevisionCommit marks a Scan whose git revision could not be resolved
// — a tarball, a vendored copy, any target outside a repository. Baseline and
// differential features degrade gracefully for such scans.
const UnknownRevisionCommit = "unknown"

// UnknownRevision is the fallback Revision for non-repository targets.
func UnknownRevision() Revision { return Revision{commit: UnknownRevisionCommit} }

// IsUnknown reports whether the revision could not be resolved from git.
func (r Revision) IsUnknown() bool { return r.commit == UnknownRevisionCommit }
