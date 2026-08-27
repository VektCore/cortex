package gate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/gate"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// mkFinding is a builder for evaluator tests.
func mkFinding(t *testing.T, sev shared.Severity, file string, cwe string) finding.Finding {
	t.Helper()
	in := finding.NewFindingInput{
		RuleID:   "test.rule",
		Severity: sev,
		Location: finding.MustNewLocation(finding.LocationInput{File: file, StartLine: 1}),
		Message:  "x",
		Source:   "semgrep",
		Snippet:  file + ":" + sev.String() + ":" + cwe,
	}
	if cwe != "" {
		c, err := finding.NewCWE(cwe).Get()
		require.NoError(t, err)
		in.CWE = shared.Some(c)
	}
	f, err := finding.New(in).Get()
	require.NoError(t, err)
	return f
}

func TestEvaluate_EmptyPolicyAlwaysPasses(t *testing.T) {
	t.Parallel()
	v := gate.Evaluate(gate.NewPolicy(nil), []finding.Finding{
		mkFinding(t, shared.SeverityCritical, "a.go", ""),
	})
	assert.True(t, v.Passed())
}

func TestEvaluate_NoFindingsAlwaysPasses(t *testing.T) {
	t.Parallel()
	rule := gate.NewRule(
		"no-critical",
		gate.NewCriteria(gate.CriteriaInput{MinSeverity: shared.Some(shared.SeverityCritical)}),
		gate.NewThreshold(gate.OpGreaterEqual, 1),
	)
	v := gate.Evaluate(gate.NewPolicy([]gate.Rule{rule}), nil)
	assert.True(t, v.Passed())
}

func TestEvaluate_FailsOnCriticalThreshold(t *testing.T) {
	t.Parallel()
	rule := gate.NewRule(
		"no-critical",
		gate.NewCriteria(gate.CriteriaInput{MinSeverity: shared.Some(shared.SeverityCritical)}),
		gate.NewThreshold(gate.OpGreaterEqual, 1),
	)
	policy := gate.NewPolicy([]gate.Rule{rule})

	findings := []finding.Finding{
		mkFinding(t, shared.SeverityHigh, "a.go", ""),     // ignored
		mkFinding(t, shared.SeverityCritical, "b.go", ""), // triggers
	}
	v := gate.Evaluate(policy, findings)
	require.True(t, v.Failed())
	require.Len(t, v.Violations(), 1)
	assert.Equal(t, 1, v.Violations()[0].Count())
	assert.Equal(t, "no-critical", v.Violations()[0].Rule().Name())
}

func TestEvaluate_FailsOnCountThreshold(t *testing.T) {
	t.Parallel()
	rule := gate.NewRule(
		"max-5-high",
		gate.NewCriteria(gate.CriteriaInput{MinSeverity: shared.Some(shared.SeverityHigh)}),
		gate.NewThreshold(gate.OpGreater, 5),
	)
	policy := gate.NewPolicy([]gate.Rule{rule})

	// Exactly 6 highs → triggers ">5".
	var findings []finding.Finding
	for i := 0; i < 6; i++ {
		findings = append(findings, mkFinding(t, shared.SeverityHigh, "f"+string(rune('a'+i))+".go", ""))
	}
	v := gate.Evaluate(policy, findings)
	assert.True(t, v.Failed())
	assert.Equal(t, 6, v.Violations()[0].Count())
}

func TestEvaluate_CWESpecificRule(t *testing.T) {
	t.Parallel()
	cwe89, _ := finding.NewCWE("CWE-89").Get()

	rule := gate.NewRule(
		"no-sqli",
		gate.NewCriteria(gate.CriteriaInput{CWEs: []finding.CWE{cwe89}}),
		gate.NewThreshold(gate.OpGreaterEqual, 1),
	)
	policy := gate.NewPolicy([]gate.Rule{rule})

	findings := []finding.Finding{
		mkFinding(t, shared.SeverityHigh, "a.go", "CWE-79"), // wrong CWE
		mkFinding(t, shared.SeverityLow, "b.go", "CWE-89"),  // triggers
	}
	v := gate.Evaluate(policy, findings)
	assert.True(t, v.Failed())
	assert.Equal(t, 1, v.Violations()[0].Count())
}

func TestEvaluate_PathPrefixIgnoresTests(t *testing.T) {
	t.Parallel()
	rule := gate.NewRule(
		"prod-no-critical",
		gate.NewCriteria(gate.CriteriaInput{
			MinSeverity: shared.Some(shared.SeverityCritical),
			PathPrefix:  []string{"src/"},
		}),
		gate.NewThreshold(gate.OpGreaterEqual, 1),
	)
	policy := gate.NewPolicy([]gate.Rule{rule})

	findings := []finding.Finding{
		mkFinding(t, shared.SeverityCritical, "tests/x.go", ""), // outside src/
		mkFinding(t, shared.SeverityCritical, "src/y.go", ""),   // triggers
	}
	v := gate.Evaluate(policy, findings)
	require.True(t, v.Failed())
	assert.Equal(t, 1, v.Violations()[0].Count())
}

func TestEvaluate_MultipleViolationsAccumulate(t *testing.T) {
	t.Parallel()
	critRule := gate.NewRule(
		"no-critical",
		gate.NewCriteria(gate.CriteriaInput{MinSeverity: shared.Some(shared.SeverityCritical)}),
		gate.NewThreshold(gate.OpGreaterEqual, 1),
	)
	highRule := gate.NewRule(
		"max-high",
		gate.NewCriteria(gate.CriteriaInput{MinSeverity: shared.Some(shared.SeverityHigh)}),
		gate.NewThreshold(gate.OpGreater, 2),
	)
	policy := gate.NewPolicy([]gate.Rule{critRule, highRule})

	findings := []finding.Finding{
		mkFinding(t, shared.SeverityCritical, "a.go", ""),
		mkFinding(t, shared.SeverityHigh, "b.go", ""),
		mkFinding(t, shared.SeverityHigh, "c.go", ""),
		mkFinding(t, shared.SeverityHigh, "d.go", ""),
	}
	v := gate.Evaluate(policy, findings)
	require.True(t, v.Failed())
	assert.Len(t, v.Violations(), 2)
}

func TestEvaluate_SamplesAreCapped(t *testing.T) {
	t.Parallel()
	rule := gate.NewRule(
		"any-high",
		gate.NewCriteria(gate.CriteriaInput{MinSeverity: shared.Some(shared.SeverityHigh)}),
		gate.NewThreshold(gate.OpGreaterEqual, 1),
	)
	policy := gate.NewPolicy([]gate.Rule{rule})

	var findings []finding.Finding
	for i := 0; i < 10; i++ {
		findings = append(findings, mkFinding(t, shared.SeverityHigh,
			"f"+string(rune('a'+i))+".go", ""))
	}
	v := gate.Evaluate(policy, findings)
	require.True(t, v.Failed())
	assert.Equal(t, 10, v.Violations()[0].Count())
	assert.LessOrEqual(t, len(v.Violations()[0].Samples()), gate.MaxSamplesPerViolation)
}

func TestThreshold_Triggers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		op    gate.Operator
		val   int
		count int
		want  bool
	}{
		{gate.OpGreater, 5, 5, false},
		{gate.OpGreater, 5, 6, true},
		{gate.OpGreaterEqual, 5, 5, true},
		{gate.OpGreaterEqual, 5, 4, false},
		{gate.OpEqual, 3, 3, true},
		{gate.OpEqual, 3, 4, false},
		{gate.OpLess, 5, 4, true},
		{gate.OpLess, 5, 5, false},
	}
	for _, c := range cases {
		th := gate.NewThreshold(c.op, c.val)
		assert.Equal(t, c.want, th.Triggers(c.count),
			"%d %s %d", c.count, c.op, c.val)
	}
}
