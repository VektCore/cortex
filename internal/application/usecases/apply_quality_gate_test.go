package usecases_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/application/usecases"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/gate"
	"github.com/vektcore/cortex/internal/domain/shared"
)

func TestApplyQualityGate_PassWhenNoFindings(t *testing.T) {
	t.Parallel()
	uc := usecases.NewApplyQualityGate()
	policy := gate.NewPolicy([]gate.Rule{
		gate.NewRule("no-critical",
			gate.NewCriteria(gate.CriteriaInput{MinSeverity: shared.Some(shared.SeverityCritical)}),
			gate.NewThreshold(gate.OpGreaterEqual, 1),
		),
	})

	resp := uc.Execute(dto.ApplyQualityGateRequest{
		Findings: nil,
		Policy:   policy,
	})
	assert.True(t, resp.Verdict.Passed())
}

func TestApplyQualityGate_FailsOnCritical(t *testing.T) {
	t.Parallel()
	uc := usecases.NewApplyQualityGate()
	policy := gate.NewPolicy([]gate.Rule{
		gate.NewRule("no-critical",
			gate.NewCriteria(gate.CriteriaInput{MinSeverity: shared.Some(shared.SeverityCritical)}),
			gate.NewThreshold(gate.OpGreaterEqual, 1),
		),
	})
	findings := []finding.Finding{
		mkFinding("a.go", shared.SeverityCritical, "semgrep"),
	}

	resp := uc.Execute(dto.ApplyQualityGateRequest{Findings: findings, Policy: policy})
	assert.True(t, resp.Verdict.Failed())
	assert.Len(t, resp.Considered, 1)
}

func TestApplyQualityGate_BaselineFiltersKnownFindings(t *testing.T) {
	t.Parallel()
	uc := usecases.NewApplyQualityGate()
	policy := gate.NewPolicy([]gate.Rule{
		gate.NewRule("no-critical",
			gate.NewCriteria(gate.CriteriaInput{MinSeverity: shared.Some(shared.SeverityCritical)}),
			gate.NewThreshold(gate.OpGreaterEqual, 1),
		),
	})

	legacy := mkFinding("legacy.go", shared.SeverityCritical, "semgrep")
	novel := mkFinding("new.go", shared.SeverityCritical, "semgrep")

	resp := uc.Execute(dto.ApplyQualityGateRequest{
		Findings: []finding.Finding{legacy, novel},
		Policy:   policy,
		Baseline: shared.Some([]finding.Finding{legacy}),
	})
	assert.True(t, resp.Verdict.Failed())
	assert.Len(t, resp.Considered, 1, "only the new finding should count")
}

func TestApplyQualityGate_BaselineEliminatesAllFindings(t *testing.T) {
	t.Parallel()
	uc := usecases.NewApplyQualityGate()
	policy := gate.NewPolicy([]gate.Rule{
		gate.NewRule("no-critical",
			gate.NewCriteria(gate.CriteriaInput{MinSeverity: shared.Some(shared.SeverityCritical)}),
			gate.NewThreshold(gate.OpGreaterEqual, 1),
		),
	})
	legacy := mkFinding("legacy.go", shared.SeverityCritical, "semgrep")

	resp := uc.Execute(dto.ApplyQualityGateRequest{
		Findings: []finding.Finding{legacy},
		Policy:   policy,
		Baseline: shared.Some([]finding.Finding{legacy}),
	})
	assert.True(t, resp.Verdict.Passed())
	assert.Empty(t, resp.Considered)
}
