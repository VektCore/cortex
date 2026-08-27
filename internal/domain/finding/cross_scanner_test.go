package finding_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

func mkCWEFinding(
	t *testing.T, file, rule, scanner, cwe string, sev shared.Severity,
) finding.Finding {
	t.Helper()

	loc, err := finding.NewLocation(finding.LocationInput{File: file, StartLine: 10}).Get()
	require.NoError(t, err)

	in := finding.NewFindingInput{
		RuleID:   finding.RuleID(rule),
		Severity: sev,
		Location: loc,
		Message:  "sqli",
		Source:   finding.ScannerName(scanner),
	}
	if cwe != "" {
		c, cErr := finding.NewCWE(cwe).Get()
		require.NoError(t, cErr)
		in.CWE = shared.Some(c)
	}

	f, err := finding.New(in).Get()
	require.NoError(t, err)
	return f
}

func TestDeduplicateCrossScanner_CollapsesSameWeakness(t *testing.T) {
	t.Parallel()

	in := []finding.Finding{
		mkCWEFinding(t, "db.py", "B608", "bandit", "CWE-89", shared.SeverityHigh),
		mkCWEFinding(t, "db.py", "python.sqlalchemy.sqli", "semgrep", "CWE-89", shared.SeverityCritical),
	}

	res := finding.DeduplicateCrossScanner(in)

	require.Len(t, res.Findings, 1, "the same weakness at the same place counts once")
	assert.Equal(t, shared.SeverityCritical, res.Findings[0].Severity(), "highest severity wins")
	assert.Equal(t, 1, res.Corroborated, "agreement between scanners is reported")
}

func TestDeduplicateCrossScanner_KeepsDifferentWeaknessesAndUnlabelled(t *testing.T) {
	t.Parallel()

	in := []finding.Finding{
		mkCWEFinding(t, "db.py", "B608", "bandit", "CWE-89", shared.SeverityHigh),
		mkCWEFinding(t, "db.py", "B602", "bandit", "CWE-78", shared.SeverityHigh),
		mkCWEFinding(t, "db.py", "custom", "eslint", "", shared.SeverityLow),
		mkCWEFinding(t, "other.py", "B608", "bandit", "CWE-89", shared.SeverityHigh),
	}

	res := finding.DeduplicateCrossScanner(in)

	assert.Len(t, res.Findings, 4, "different CWEs, files and unlabelled findings all survive")
	assert.Equal(t, 0, res.Corroborated)
}
