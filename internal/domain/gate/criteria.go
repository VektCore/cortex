package gate

import (
	"strings"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// Criteria selects the subset of findings that a rule cares about.
// An empty Criteria matches every finding.
type Criteria struct {
	minSeverity mo.Option[shared.Severity]
	cwes        []finding.CWE
	pathPrefix  []string
}

// CriteriaInput is the constructor parameter struct.
//
// PathPrefix uses simple prefix matching (no globbing) — this keeps the
// domain pure and deterministic. More expressive matching can be added
// via an injected port later if needed.
type CriteriaInput struct {
	MinSeverity mo.Option[shared.Severity]
	CWEs        []finding.CWE
	PathPrefix  []string
}

// NewCriteria constructs a Criteria. All slices are defensively copied.
func NewCriteria(in CriteriaInput) Criteria {
	return Criteria{
		minSeverity: in.MinSeverity,
		cwes:        append([]finding.CWE(nil), in.CWEs...),
		pathPrefix:  append([]string(nil), in.PathPrefix...),
	}
}

// Matches reports whether f satisfies every filter in the Criteria.
// A Criteria with no filters matches every Finding.
func (c Criteria) Matches(f finding.Finding) bool {
	if sev, ok := c.minSeverity.Get(); ok && !f.Severity().AtLeast(sev) {
		return false
	}
	return c.matchesCWE(f) && c.matchesPath(f)
}

// matchesCWE is true when no CWE filter is set, or the finding carries one of
// the listed weaknesses. A finding with no CWE never satisfies a CWE filter.
func (c Criteria) matchesCWE(f finding.Finding) bool {
	if len(c.cwes) == 0 {
		return true
	}
	fcwe, hasCWE := f.CWE().Get()
	if !hasCWE {
		return false
	}
	for _, want := range c.cwes {
		if fcwe == want {
			return true
		}
	}
	return false
}

// matchesPath is true when no path filter is set, or the finding's file starts
// with one of the prefixes.
func (c Criteria) matchesPath(f finding.Finding) bool {
	if len(c.pathPrefix) == 0 {
		return true
	}
	file := f.Location().File()
	for _, prefix := range c.pathPrefix {
		if strings.HasPrefix(file, prefix) {
			return true
		}
	}
	return false
}
