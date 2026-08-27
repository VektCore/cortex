package finding_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vektcore/cortex/internal/domain/finding"
)

func TestDiffNew_EmptyBaseline_KeepsAll(t *testing.T) {
	t.Parallel()
	a := build(t, withSnippet("a"))
	b := build(t, withSnippet("b"))
	out := finding.DiffNew([]finding.Finding{a, b}, nil)
	assert.Len(t, out, 2)
}

func TestDiffNew_RemovesKnown(t *testing.T) {
	t.Parallel()
	preExisting := build(t, withFile("a.go"), withSnippet("legacy"))
	novel := build(t, withFile("b.go"), withSnippet("new"))

	out := finding.DiffNew(
		[]finding.Finding{preExisting, novel},
		[]finding.Finding{preExisting},
	)
	assert.Len(t, out, 1)
	assert.Equal(t, novel.Fingerprint(), out[0].Fingerprint())
}

func TestDiffFixed_ReturnsResolved(t *testing.T) {
	t.Parallel()
	stillThere := build(t, withFile("a.go"))
	wasFixed := build(t, withFile("b.go"))

	out := finding.DiffFixed(
		[]finding.Finding{stillThere},
		[]finding.Finding{stillThere, wasFixed},
	)
	assert.Len(t, out, 1)
	assert.Equal(t, wasFixed.Fingerprint(), out[0].Fingerprint())
}
