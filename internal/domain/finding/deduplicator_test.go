package finding_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

func TestDeduplicate_EmptyInput(t *testing.T) {
	t.Parallel()
	assert.Nil(t, finding.Deduplicate(nil))
	assert.Nil(t, finding.Deduplicate([]finding.Finding{}))
}

func TestDeduplicate_CollapsesSameFingerprint(t *testing.T) {
	t.Parallel()
	// Two findings with same RuleID + same Location + same snippet → same FP.
	a := build(t, withSnippet("exec(query)"))
	b := build(t, withSnippet("exec(query)"))
	assert.Equal(t, a.Fingerprint(), b.Fingerprint(), "precondition: same fingerprint")

	out := finding.Deduplicate([]finding.Finding{a, b})
	assert.Len(t, out, 1)
}

func TestDeduplicate_HighestSeverityWins(t *testing.T) {
	t.Parallel()
	low := build(t, withSnippet("code"), withSeverity(shared.SeverityLow))
	high := build(t, withSnippet("code"), withSeverity(shared.SeverityCritical))
	assert.Equal(t, low.Fingerprint(), high.Fingerprint(), "precondition")

	out := finding.Deduplicate([]finding.Finding{low, high})
	assert.Len(t, out, 1)
	assert.Equal(t, shared.SeverityCritical, out[0].Severity())
}

func TestDeduplicate_PreservesOrder(t *testing.T) {
	t.Parallel()
	a := build(t, withFile("a.go"), withSnippet("a"))
	b := build(t, withFile("b.go"), withSnippet("b"))
	c := build(t, withFile("c.go"), withSnippet("c"))

	out := finding.Deduplicate([]finding.Finding{a, b, c, a, b})
	assert.Len(t, out, 3)
	assert.Equal(t, a.Fingerprint(), out[0].Fingerprint())
	assert.Equal(t, b.Fingerprint(), out[1].Fingerprint())
	assert.Equal(t, c.Fingerprint(), out[2].Fingerprint())
}

func TestDeduplicateByScanner_KeepsCrossScannerHits(t *testing.T) {
	t.Parallel()
	fromSemgrep := build(t, withSnippet("x"), withSource("semgrep"))
	fromBandit := build(t, withSnippet("x"), withSource("bandit"))
	assert.Equal(t, fromSemgrep.Fingerprint(), fromBandit.Fingerprint())

	out := finding.DeduplicateByScanner([]finding.Finding{fromSemgrep, fromBandit, fromSemgrep})
	assert.Len(t, out, 2, "should keep one per (fingerprint, scanner)")
}
