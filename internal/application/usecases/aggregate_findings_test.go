package usecases_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/application/usecases"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

func TestAggregateFindings_MergesAndDedupes(t *testing.T) {
	t.Parallel()
	uc := usecases.NewAggregateFindings()

	a := mkFinding("a.go", shared.SeverityHigh, "semgrep")
	b := mkFinding("b.go", shared.SeverityHigh, "semgrep")
	// duplicate of a from another scanner — same fingerprint, dedupe
	dupA := mkFinding("a.go", shared.SeverityHigh, "bandit")

	resp := uc.Execute(dto.AggregateFindingsRequest{
		Inputs: [][]finding.Finding{{a, b}, {dupA}},
	})
	assert.Len(t, resp.Findings, 2)
}

func TestAggregateFindings_EmptyInput(t *testing.T) {
	t.Parallel()
	uc := usecases.NewAggregateFindings()
	resp := uc.Execute(dto.AggregateFindingsRequest{Inputs: nil})
	assert.Empty(t, resp.Findings)
}
