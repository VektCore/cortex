package services

import (
	"context"
	"strings"
	"time"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/application/usecases"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// Pipeline is the application service that orchestrates the full
// scan → aggregate → gate → publish flow as a single transaction.
//
// It is the only piece that knows the order of operations. Every use
// case it composes remains independently usable.
type Pipeline struct {
	execute   *usecases.ExecuteScan
	aggregate *usecases.AggregateFindings
	gate      *usecases.ApplyQualityGate
	publish   *usecases.PublishResults
	codec     ports.SarifCodec
	logger    ports.Logger
}

// PipelineDeps groups Pipeline's dependencies.
type PipelineDeps struct {
	ExecuteScan       *usecases.ExecuteScan
	AggregateFindings *usecases.AggregateFindings
	ApplyQualityGate  *usecases.ApplyQualityGate
	PublishResults    *usecases.PublishResults
	Codec             ports.SarifCodec
	Logger            ports.Logger
}

// NewPipeline wires the service.
func NewPipeline(d PipelineDeps) *Pipeline {
	return &Pipeline{
		execute:   d.ExecuteScan,
		aggregate: d.AggregateFindings,
		gate:      d.ApplyQualityGate,
		publish:   d.PublishResults,
		codec:     d.Codec,
		logger:    d.Logger,
	}
}

// Execute drives the full pipeline. A non-error Result is returned even
// when the gate fails — gate failures are signaled by Verdict, not by
// error. Errors come only from infrastructure failures upstream of
// publishing (e.g. git not present, no scanners runnable).
func (p *Pipeline) Execute(
	ctx context.Context, req dto.PipelineRequest,
) mo.Result[dto.PipelineResponse] {
	// 1. Scan.
	scanResp, err := p.execute.Execute(ctx, dto.ExecuteScanRequest{
		TargetPath:   req.TargetPath,
		Scanners:     req.Scanners,
		Languages:    req.Languages,
		Settings:     req.Settings,
		Exclude:      req.Exclude,
		Escalations:  req.Escalations,
		Reachability: req.Reachability,
	}).Get()
	if err != nil {
		return shared.Err[dto.PipelineResponse](err)
	}

	// 2. Aggregate.
	aggResp := p.aggregate.Execute(dto.AggregateFindingsRequest{
		Inputs:       [][]finding.Finding{scanResp.Findings},
		CrossScanner: req.CrossScanner,
	})

	// 3. Apply gate.
	gateFindings := applyIgnoreFilters(aggResp.Findings, req.Ignores)
	gateResp := p.gate.Execute(dto.ApplyQualityGateRequest{
		Findings: gateFindings,
		Policy:   req.Policy,
		Baseline: req.Baseline,
	})

	// 4. Serialize SARIF for publishers.
	var sarif []byte
	if !req.DryRun {
		sarifRes := p.codec.Write(aggResp.Findings, ports.SarifMetadata{
			Tool:     "cortex",
			Version:  "0.1.0",
			Revision: scanResp.Scan.Revision(),
		})
		s, sarifErr := sarifRes.Get()
		if sarifErr != nil {
			p.logger.Warn("sarif encoding failed; skipping publish",
				ports.F("error", sarifErr.Error()))
		} else {
			sarif = s
		}
	}

	// 5. Publish (unless dry run or SARIF unavailable).
	var pubResp dto.PublishResultsResponse
	pubResp.Errors = map[string]error{}
	if !req.DryRun && sarif != nil {
		pubResp = p.publish.Execute(ctx, dto.PublishResultsRequest{
			Scan:     scanResp.Scan,
			Findings: aggResp.Findings,
			SARIF:    sarif,
			Targets:  req.Publishers,
		})
	}

	// 6. Surface non-fatal errors.
	errs := make([]error, 0)
	for _, e := range scanResp.Errors {
		errs = append(errs, e)
	}
	for _, e := range pubResp.Errors {
		errs = append(errs, e)
	}

	return shared.Ok(dto.PipelineResponse{
		Scan:     scanResp.Scan,
		Verdict:  gateResp.Verdict,
		Findings: aggResp.Findings,
		Receipts: pubResp.Receipts,
		Errors:   errs,
	})
}

func applyIgnoreFilters(findings []finding.Finding, ignores []dto.IgnoreFilter) []finding.Finding {
	if len(ignores) == 0 {
		return findings
	}
	now := time.Now()
	out := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		suppressed := false
		for _, ig := range ignores {
			if matchesIgnore(f, ig, now) {
				suppressed = true
				break
			}
		}
		if !suppressed {
			out = append(out, f)
		}
	}
	return out
}

func matchesIgnore(f finding.Finding, ig dto.IgnoreFilter, now time.Time) bool {
	if !ig.ExpiresAt.IsZero() && now.After(ig.ExpiresAt) {
		return false
	}
	if ig.RuleID != "" && !strings.EqualFold(f.RuleID().String(), ig.RuleID) {
		return false
	}
	if ig.PathPrefix != "" && !strings.HasPrefix(f.Location().File(), ig.PathPrefix) {
		return false
	}
	return true
}
