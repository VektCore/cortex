package services_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/samber/mo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/application/services"
	"github.com/vektcore/cortex/internal/application/usecases"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/gate"
	"github.com/vektcore/cortex/internal/domain/scan"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// ---------- Fakes ----------

type fakeScanner struct {
	name     finding.ScannerName
	langs    []shared.Language
	findings []finding.Finding
}

func (f *fakeScanner) Name() finding.ScannerName             { return f.name }
func (f *fakeScanner) SupportedLanguages() []shared.Language { return f.langs }
func (f *fakeScanner) Available(_ context.Context) bool      { return true }
func (f *fakeScanner) Scan(_ context.Context, _ ports.ScanRequest) mo.Result[ports.ScanOutput] {
	return shared.Ok(ports.ScanOutput{Scanner: f.name, Findings: f.findings})
}

type fakeRegistry struct {
	scanners map[finding.ScannerName]ports.Scanner
}

func newRegistry(ss ...ports.Scanner) *fakeRegistry {
	r := &fakeRegistry{scanners: map[finding.ScannerName]ports.Scanner{}}
	for _, s := range ss {
		r.scanners[s.Name()] = s
	}
	return r
}

func (r *fakeRegistry) Register(s ports.Scanner) { r.scanners[s.Name()] = s }
func (r *fakeRegistry) Get(n finding.ScannerName) mo.Option[ports.Scanner] {
	if s, ok := r.scanners[n]; ok {
		return shared.Some(s)
	}
	return shared.None[ports.Scanner]()
}
func (r *fakeRegistry) All() []ports.Scanner {
	out := make([]ports.Scanner, 0, len(r.scanners))
	for _, s := range r.scanners {
		out = append(out, s)
	}
	return out
}
func (r *fakeRegistry) ForLanguage(_ shared.Language) []ports.Scanner { return r.All() }
func (r *fakeRegistry) ForLanguages(_ []shared.Language) []ports.Scanner {
	return r.All()
}

type fakeDetector struct{ langs []shared.Language }

func (f *fakeDetector) Detect(_ context.Context, _ string, _ []string) mo.Result[[]shared.Language] {
	return shared.Ok(f.langs)
}

type fakeGit struct{ rev scan.Revision }

func (f *fakeGit) CurrentRevision(_ context.Context, _ string) mo.Result[scan.Revision] {
	return shared.Ok(f.rev)
}
func (f *fakeGit) ChangedLines(
	_ context.Context, _, _ string,
) mo.Result[ports.ChangedLines] {
	return shared.Ok(ports.ChangedLines{})
}

func (f *fakeGit) ChangedFiles(_ context.Context, _, _ string) mo.Result[[]string] {
	return shared.Ok[[]string](nil)
}

type fakeIDGen struct{ n int }

func (g *fakeIDGen) NewScanID() scan.ID {
	g.n++
	return scan.ID(fmt.Sprintf("s-%d", g.n))
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type noopLogger struct{}

func (noopLogger) Debug(string, ...ports.Field) {}
func (noopLogger) Info(string, ...ports.Field)  {}
func (noopLogger) Warn(string, ...ports.Field)  {}
func (noopLogger) Error(string, ...ports.Field) {}

type fakeCodec struct{ failWrite bool }

func (c *fakeCodec) Parse(_ []byte) mo.Result[[]finding.Finding] {
	return shared.Ok[[]finding.Finding](nil)
}
func (c *fakeCodec) Write(_ []finding.Finding, _ ports.SarifMetadata) mo.Result[[]byte] {
	if c.failWrite {
		return shared.Err[[]byte](errors.New("encode failure"))
	}
	return shared.Ok([]byte(`{"version":"2.1.0","runs":[]}`))
}
func (c *fakeCodec) Merge(_ [][]byte) mo.Result[[]byte] { return shared.Ok([]byte(`{}`)) }

type fakePublisher struct {
	name  string
	err   error
	calls int
}

func (p *fakePublisher) Name() string { return p.name }
func (p *fakePublisher) Publish(_ context.Context, _ ports.PublishRequest) mo.Result[ports.PublishReceipt] {
	p.calls++
	if p.err != nil {
		return shared.Err[ports.PublishReceipt](p.err)
	}
	return shared.Ok(ports.PublishReceipt{Publisher: p.name, Reference: "r"})
}

// ---------- Helpers ----------

func mkFinding(t *testing.T, file string, sev shared.Severity) finding.Finding {
	t.Helper()
	loc := finding.MustNewLocation(finding.LocationInput{File: file, StartLine: 1})
	f, err := finding.New(finding.NewFindingInput{
		RuleID:   "rule",
		Severity: sev,
		Location: loc,
		Source:   "fake",
		Snippet:  file + sev.String(),
	}).Get()
	require.NoError(t, err)
	return f
}

func mkRev() scan.Revision {
	r, _ := scan.NewRevision("abc", "main").Get()
	return r
}

func buildPipeline(t *testing.T, scanners []ports.Scanner, publishers map[string]ports.Publisher, codec ports.SarifCodec) *services.Pipeline {
	t.Helper()
	exec := usecases.NewExecuteScan(usecases.ExecuteScanDeps{
		Registry: newRegistry(scanners...),
		Detector: &fakeDetector{langs: []shared.Language{shared.LanguagePython}},
		Git:      &fakeGit{rev: mkRev()},
		IDGen:    &fakeIDGen{},
		Clock:    fixedClock{t: time.Now()},
		Logger:   noopLogger{},
	})
	return services.NewPipeline(services.PipelineDeps{
		ExecuteScan:       exec,
		AggregateFindings: usecases.NewAggregateFindings(),
		ApplyQualityGate:  usecases.NewApplyQualityGate(),
		PublishResults:    usecases.NewPublishResults(usecases.PublishResultsDeps{Publishers: publishers, Logger: noopLogger{}}),
		Codec:             codec,
		Logger:            noopLogger{},
	})
}

// ---------- Tests ----------

func TestPipeline_HappyPath_GatePasses(t *testing.T) {
	t.Parallel()
	sc := &fakeScanner{
		name:     "semgrep",
		langs:    []shared.Language{shared.LanguagePython},
		findings: []finding.Finding{mkFinding(t, "py/a.py", shared.SeverityLow)},
	}
	pub := &fakePublisher{name: "filesystem"}
	pipe := buildPipeline(t,
		[]ports.Scanner{sc},
		map[string]ports.Publisher{pub.name: pub},
		&fakeCodec{},
	)

	policy := gate.NewPolicy([]gate.Rule{
		gate.NewRule("no-critical",
			gate.NewCriteria(gate.CriteriaInput{MinSeverity: shared.Some(shared.SeverityCritical)}),
			gate.NewThreshold(gate.OpGreaterEqual, 1),
		),
	})

	resp, err := pipe.Execute(context.Background(), dto.PipelineRequest{
		TargetPath: "/r",
		Policy:     policy,
	}).Get()
	require.NoError(t, err)
	assert.True(t, resp.Verdict.Passed())
	assert.Len(t, resp.Findings, 1)
	assert.Equal(t, 1, pub.calls)
	assert.Empty(t, resp.Errors)
}

func TestPipeline_GateFails_StillPublishes(t *testing.T) {
	t.Parallel()
	sc := &fakeScanner{
		name:     "semgrep",
		langs:    []shared.Language{shared.LanguagePython},
		findings: []finding.Finding{mkFinding(t, "py/a.py", shared.SeverityCritical)},
	}
	pub := &fakePublisher{name: "filesystem"}
	pipe := buildPipeline(t,
		[]ports.Scanner{sc},
		map[string]ports.Publisher{pub.name: pub},
		&fakeCodec{},
	)

	policy := gate.NewPolicy([]gate.Rule{
		gate.NewRule("no-critical",
			gate.NewCriteria(gate.CriteriaInput{MinSeverity: shared.Some(shared.SeverityCritical)}),
			gate.NewThreshold(gate.OpGreaterEqual, 1),
		),
	})

	resp, err := pipe.Execute(context.Background(), dto.PipelineRequest{
		TargetPath: "/r",
		Policy:     policy,
	}).Get()
	require.NoError(t, err, "gate failure must NOT propagate as a use-case error")
	assert.True(t, resp.Verdict.Failed())
	assert.Equal(t, 1, pub.calls, "publish runs even when gate fails — exit code is the gate signal")
}

func TestPipeline_DryRun_SkipsPublish(t *testing.T) {
	t.Parallel()
	pub := &fakePublisher{name: "filesystem"}
	pipe := buildPipeline(t,
		[]ports.Scanner{&fakeScanner{name: "x", langs: []shared.Language{shared.LanguagePython}}},
		map[string]ports.Publisher{pub.name: pub},
		&fakeCodec{},
	)
	_, err := pipe.Execute(context.Background(), dto.PipelineRequest{
		TargetPath: "/r",
		Policy:     gate.NewPolicy(nil),
		DryRun:     true,
	}).Get()
	require.NoError(t, err)
	assert.Equal(t, 0, pub.calls)
}

func TestPipeline_SarifEncodingFailure_KeepsGateButSkipsPublish(t *testing.T) {
	t.Parallel()
	pub := &fakePublisher{name: "filesystem"}
	pipe := buildPipeline(t,
		[]ports.Scanner{&fakeScanner{name: "x", langs: []shared.Language{shared.LanguagePython}}},
		map[string]ports.Publisher{pub.name: pub},
		&fakeCodec{failWrite: true},
	)
	resp, err := pipe.Execute(context.Background(), dto.PipelineRequest{
		TargetPath: "/r",
		Policy:     gate.NewPolicy(nil),
	}).Get()
	require.NoError(t, err)
	assert.True(t, resp.Verdict.Passed())
	assert.Equal(t, 0, pub.calls, "without SARIF, publish is skipped")
}
