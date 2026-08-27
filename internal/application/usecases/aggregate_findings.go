package usecases

import (
	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/domain/finding"
)

// AggregateFindings merges N batches of findings (one per scanner) and
// removes duplicates. The heavy lifting is delegated to the domain's
// Deduplicate function — this use case exists only to define the
// application boundary and to keep call sites uniform.
type AggregateFindings struct{}

// NewAggregateFindings is the constructor.
func NewAggregateFindings() *AggregateFindings { return &AggregateFindings{} }

// Execute is pure: no I/O, no logging.
func (uc *AggregateFindings) Execute(req dto.AggregateFindingsRequest) dto.AggregateFindingsResponse {
	total := 0
	for _, batch := range req.Inputs {
		total += len(batch)
	}
	merged := make([]finding.Finding, 0, total)
	for _, batch := range req.Inputs {
		merged = append(merged, batch...)
	}

	deduped := finding.Deduplicate(merged)
	if !req.CrossScanner {
		return dto.AggregateFindingsResponse{Findings: deduped}
	}

	across := finding.DeduplicateCrossScanner(deduped)
	return dto.AggregateFindingsResponse{
		Findings:     across.Findings,
		Corroborated: across.Corroborated,
	}
}
