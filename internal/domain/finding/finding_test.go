package finding_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

func TestNewFinding_HappyPath(t *testing.T) {
	t.Parallel()
	cweRes := finding.NewCWE("CWE-89")
	cwe, err := cweRes.Get()
	require.NoError(t, err)

	in := finding.NewFindingInput{
		RuleID:   "semgrep.python.sqli",
		Severity: shared.SeverityCritical,
		Location: finding.MustNewLocation(finding.LocationInput{
			File: "python/db.py", StartLine: 12,
		}),
		Message:   "possible SQL injection via string concatenation",
		Source:    "semgrep",
		Snippet:   "exec(query + user_input)",
		CWE:       shared.Some(cwe),
		Languages: []shared.Language{shared.LanguagePython},
	}

	r := finding.New(in)
	f, err := r.Get()
	require.NoError(t, err)

	assert.Equal(t, finding.RuleID("semgrep.python.sqli"), f.RuleID())
	assert.Equal(t, shared.SeverityCritical, f.Severity())
	assert.Equal(t, finding.Message("possible SQL injection via string concatenation"), f.Message())
	assert.Equal(t, finding.ScannerName("semgrep"), f.Source())
	assert.True(t, f.HasCWE(cwe))
	assert.Len(t, string(f.Fingerprint()), finding.FingerprintLength)
}

func TestNewFinding_Invariants(t *testing.T) {
	t.Parallel()
	base := finding.NewFindingInput{
		RuleID:   "r",
		Severity: shared.SeverityHigh,
		Location: finding.MustNewLocation(finding.LocationInput{File: "a.go", StartLine: 1}),
		Source:   "semgrep",
	}

	cases := map[string]func(in *finding.NewFindingInput){
		"empty rule":   func(in *finding.NewFindingInput) { in.RuleID = "" },
		"bad severity": func(in *finding.NewFindingInput) { in.Severity = -1 },
		"no location":  func(in *finding.NewFindingInput) { in.Location = finding.Location{} },
		"no source":    func(in *finding.NewFindingInput) { in.Source = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := base
			mutate(&in)
			_, err := finding.New(in).Get()
			assert.Error(t, err)
		})
	}
}

func TestNewCWE(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"89":     "CWE-89",
		"CWE-89": "CWE-89",
		"cwe-22": "CWE-22",
		"  611 ": "CWE-611",
	}
	for raw, want := range cases {
		c, err := finding.NewCWE(raw).Get()
		require.NoError(t, err, "input=%q", raw)
		assert.Equal(t, want, c.String())
	}

	for _, bad := range []string{"", "CWE-", "not-a-number", "CWE-abc"} {
		_, err := finding.NewCWE(bad).Get()
		assert.Error(t, err, "input=%q", bad)
	}
}
