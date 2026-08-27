package usecases

import (
	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/gate"
)

// ApplyQualityGate is the use case that turns a set of findings into a
// pass/fail Verdict. It optionally filters by a baseline (only newly
// introduced findings count).
//
// The use case itself has no dependencies — all logic lives in the
// domain. Keeping it as a struct gives the CLI a uniform call shape
// across every use case.
type ApplyQualityGate struct{}

// NewApplyQualityGate is the constructor.
func NewApplyQualityGate() *ApplyQualityGate { return &ApplyQualityGate{} }

// Execute is pure.
func (uc *ApplyQualityGate) Execute(req dto.ApplyQualityGateRequest) dto.ApplyQualityGateResponse {
	considered := req.Findings
	if baseline, ok := req.Baseline.Get(); ok {
		considered = finding.DiffNew(req.Findings, baseline)
	}
	return dto.ApplyQualityGateResponse{
		Verdict:    gate.Evaluate(req.Policy, considered),
		Considered: considered,
	}
}
