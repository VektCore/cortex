package ruleset_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/ruleset"
	"github.com/vektcore/cortex/internal/domain/shared"
)

func mk(t *testing.T, rule, scanner string, sev shared.Severity, cwe string) finding.Finding {
	t.Helper()

	loc, err := finding.NewLocation(finding.LocationInput{File: "a.py", StartLine: 1}).Get()
	require.NoError(t, err)

	in := finding.NewFindingInput{
		RuleID:   finding.RuleID(rule),
		Severity: sev,
		Location: loc,
		Message:  "m",
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

func TestCWEFor_ScannersThatEmitNone(t *testing.T) {
	t.Parallel()

	cases := []struct{ scanner, rule, want string }{
		{"ESLint", "security/detect-child-process", "CWE-78"},
		{"ESLint", "detect-object-injection", "CWE-1321"},
		{"gitleaks", "generic-api-key", "CWE-798"},
		{"Bandit", "B608", "CWE-89"},
		{"Bandit", "b101", "CWE-703"},
		{"Bandit", "B602", "CWE-78"},
	}

	for _, c := range cases {
		got, ok := ruleset.CWEFor(finding.ScannerName(c.scanner), finding.RuleID(c.rule))
		require.True(t, ok, "%s/%s should map", c.scanner, c.rule)
		assert.Equal(t, c.want, got.String())
	}

	_, ok := ruleset.CWEFor("Semgrep OSS", "some.unknown.rule")
	assert.False(t, ok, "an unknown rule must stay without a CWE rather than be guessed")

	// Importing a dangerous module is not the exploit; B4xx must stay unmapped.
	_, importMapped := ruleset.CWEFor("Bandit", "B403")
	assert.False(t, importMapped, "blacklist-import rules must not carry the exploit's CWE")
}

func TestEnrichCWE_NeverOverwritesTheScanner(t *testing.T) {
	t.Parallel()

	// The table says B608 is CWE-89; the scanner said CWE-943. The scanner wins.
	in := []finding.Finding{
		mk(t, "B608", "Bandit", shared.SeverityHigh, "CWE-943"),
		mk(t, "B608", "Bandit", shared.SeverityHigh, ""),
	}

	out := ruleset.EnrichCWE(in)

	first, _ := out[0].CWE().Get()
	second, _ := out[1].CWE().Get()
	assert.Equal(t, "CWE-943", first.String())
	assert.Equal(t, "CWE-89", second.String())
}

func TestEscalate_OnlyRaises(t *testing.T) {
	t.Parallel()

	policy := ruleset.DefaultEscalations()

	in := []finding.Finding{
		mk(t, "B608", "Bandit", shared.SeverityMedium, "CWE-89"),     // → critical
		mk(t, "x", "Semgrep OSS", shared.SeverityCritical, "CWE-22"), // stays critical
		mk(t, "y", "Semgrep OSS", shared.SeverityLow, ""),            // no CWE, untouched
	}

	out := ruleset.Escalate(in, policy)

	assert.Equal(t, shared.SeverityCritical, out[0].Severity(), "SQLi must reach critical")
	assert.Equal(t, shared.SeverityCritical, out[1].Severity(), "a policy entry must never downgrade")
	assert.Equal(t, shared.SeverityLow, out[2].Severity())
}
