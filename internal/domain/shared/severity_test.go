package shared_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vektcore/cortex/internal/domain/shared"
)

func TestSeverity_Ordering(t *testing.T) {
	t.Parallel()
	assert.True(t, shared.SeverityCritical.AtLeast(shared.SeverityHigh))
	assert.True(t, shared.SeverityHigh.AtLeast(shared.SeverityMedium))
	assert.True(t, shared.SeverityMedium.AtLeast(shared.SeverityLow))
	assert.True(t, shared.SeverityLow.AtLeast(shared.SeverityInfo))
	assert.False(t, shared.SeverityInfo.AtLeast(shared.SeverityLow))
}

func TestSeverity_String(t *testing.T) {
	t.Parallel()
	cases := map[shared.Severity]string{
		shared.SeverityInfo:     "info",
		shared.SeverityLow:      "low",
		shared.SeverityMedium:   "medium",
		shared.SeverityHigh:     "high",
		shared.SeverityCritical: "critical",
	}
	for s, want := range cases {
		assert.Equal(t, want, s.String())
	}
}

func TestParseSeverity(t *testing.T) {
	t.Parallel()
	cases := map[string]shared.Severity{
		"info":           shared.SeverityInfo,
		"note":           shared.SeverityInfo,
		" Low ":          shared.SeverityLow,
		"warning":        shared.SeverityMedium,
		"WARN":           shared.SeverityMedium,
		"error":          shared.SeverityHigh,
		"critical":       shared.SeverityCritical,
		"blocker":        shared.SeverityCritical,
		"something-else": shared.SeverityInfo, // unknown → info
	}
	for raw, want := range cases {
		assert.Equal(t, want, shared.ParseSeverity(raw), "input=%q", raw)
	}
}
