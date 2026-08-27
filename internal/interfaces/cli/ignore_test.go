package cli

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

func mkFinding(t *testing.T, file, ruleID string) finding.Finding {
	t.Helper()

	loc, err := finding.NewLocation(finding.LocationInput{File: file, StartLine: 1}).Get()
	require.NoError(t, err)

	f, err := finding.New(finding.NewFindingInput{
		RuleID:   finding.RuleID(ruleID),
		Source:   finding.ScannerName("bandit"),
		Severity: shared.SeverityLow,
		Message:  finding.Message("assert used"),
		Location: loc,
	}).Get()
	require.NoError(t, err)

	return f
}

func TestApplyIgnoreFilters_PathForms(t *testing.T) {
	t.Parallel()

	findings := []finding.Finding{
		mkFinding(t, "services/vulnerability/tests/test_domain.py", "B101"),
		mkFinding(t, "tests/test_api.py", "B101"),
		mkFinding(t, "services/vulnerability/app.py", "B101"),
	}

	// A bare directory name suppresses it at any depth, so production code
	// keeps being gated.
	kept := applyIgnoreFilters(findings, []dto.IgnoreFilter{
		{RuleID: "B101", PathPrefix: "tests/"},
	})

	require.Len(t, kept, 1)
	assert.Equal(t, "services/vulnerability/app.py", kept[0].Location().File())
}

func TestApplyIgnoreFilters_GlobAndExpiry(t *testing.T) {
	t.Parallel()

	findings := []finding.Finding{
		mkFinding(t, "services/identity/tests/test_login.py", "B105"),
	}

	glob := applyIgnoreFilters(findings, []dto.IgnoreFilter{
		{PathPrefix: "services/*/tests/*"},
	})
	assert.Empty(t, glob, "glob pattern must suppress the finding")

	expired := applyIgnoreFilters(findings, []dto.IgnoreFilter{
		{PathPrefix: "services/*/tests/*", ExpiresAt: time.Now().Add(-time.Hour)},
	})
	assert.Len(t, expired, 1, "an expired entry must stop suppressing")
}

func TestApplyIgnoreFilters_RuleIDMustMatch(t *testing.T) {
	t.Parallel()

	findings := []finding.Finding{mkFinding(t, "tests/test_api.py", "B101")}

	kept := applyIgnoreFilters(findings, []dto.IgnoreFilter{
		{RuleID: "B999", PathPrefix: "tests/"},
	})
	assert.Len(t, kept, 1, "a different rule id must not be suppressed")
}
