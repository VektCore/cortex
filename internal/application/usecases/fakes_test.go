package usecases_test

import (
	"context"
	"fmt"
	"time"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/scan"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// ---------- Scanner ----------

type fakeScanner struct {
	name     finding.ScannerName
	langs    []shared.Language
	findings []finding.Finding
	sarif    []byte
	err      error
	calls    int
}

func (f *fakeScanner) Name() finding.ScannerName             { return f.name }
func (f *fakeScanner) SupportedLanguages() []shared.Language { return f.langs }
func (f *fakeScanner) Available(_ context.Context) bool      { return true }

func (f *fakeScanner) Scan(_ context.Context, _ ports.ScanRequest) mo.Result[ports.ScanOutput] {
	f.calls++
	if f.err != nil {
		return shared.Err[ports.ScanOutput](f.err)
	}
	return shared.Ok(ports.ScanOutput{
		Scanner:  f.name,
		Findings: f.findings,
		RawSARIF: f.sarif,
	})
}

// ---------- ScannerRegistry ----------

type fakeRegistry struct {
	scanners map[finding.ScannerName]ports.Scanner
}

func newFakeRegistry(ss ...ports.Scanner) *fakeRegistry {
	r := &fakeRegistry{scanners: map[finding.ScannerName]ports.Scanner{}}
	for _, s := range ss {
		r.scanners[s.Name()] = s
	}
	return r
}

func (r *fakeRegistry) Register(s ports.Scanner) { r.scanners[s.Name()] = s }

func (r *fakeRegistry) Get(name finding.ScannerName) mo.Option[ports.Scanner] {
	s, ok := r.scanners[name]
	if !ok {
		return shared.None[ports.Scanner]()
	}
	return shared.Some(s)
}

func (r *fakeRegistry) All() []ports.Scanner {
	out := make([]ports.Scanner, 0, len(r.scanners))
	for _, s := range r.scanners {
		out = append(out, s)
	}
	return out
}

func (r *fakeRegistry) ForLanguage(lang shared.Language) []ports.Scanner {
	out := make([]ports.Scanner, 0)
	for _, s := range r.scanners {
		for _, l := range s.SupportedLanguages() {
			if l == lang {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

func (r *fakeRegistry) ForLanguages(langs []shared.Language) []ports.Scanner {
	seen := make(map[finding.ScannerName]struct{})
	out := make([]ports.Scanner, 0)
	for _, l := range langs {
		for _, s := range r.ForLanguage(l) {
			if _, dup := seen[s.Name()]; dup {
				continue
			}
			seen[s.Name()] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// ---------- LanguageDetector ----------

type fakeDetector struct {
	languages []shared.Language
	err       error
}

func (f *fakeDetector) Detect(_ context.Context, _ string, _ []string) mo.Result[[]shared.Language] {
	if f.err != nil {
		return shared.Err[[]shared.Language](f.err)
	}
	return shared.Ok(f.languages)
}

// ---------- GitRepository ----------

type fakeGit struct {
	revision     scan.Revision
	changed      []string
	changedLines ports.ChangedLines
	err          error
}

func (f *fakeGit) CurrentRevision(_ context.Context, _ string) mo.Result[scan.Revision] {
	if f.err != nil {
		return shared.Err[scan.Revision](f.err)
	}
	return shared.Ok(f.revision)
}

func (f *fakeGit) ChangedLines(
	_ context.Context, _, _ string,
) mo.Result[ports.ChangedLines] {
	if f.err != nil {
		return shared.Err[ports.ChangedLines](f.err)
	}
	return shared.Ok(f.changedLines)
}

func (f *fakeGit) ChangedFiles(_ context.Context, _, _ string) mo.Result[[]string] {
	return shared.Ok(f.changed)
}

// ---------- IDGenerator ----------

type fakeIDGen struct{ counter int }

func (f *fakeIDGen) NewScanID() scan.ID {
	f.counter++
	return scan.ID(fmt.Sprintf("scan-%d", f.counter))
}

// ---------- Clock ----------

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// ---------- Logger ----------

type noopLogger struct{}

func (noopLogger) Debug(string, ...ports.Field) {}
func (noopLogger) Info(string, ...ports.Field)  {}
func (noopLogger) Warn(string, ...ports.Field)  {}
func (noopLogger) Error(string, ...ports.Field) {}

// ---------- Publisher ----------

type fakePublisher struct {
	name  string
	err   error
	calls int
}

func (f *fakePublisher) Name() string { return f.name }

func (f *fakePublisher) Publish(_ context.Context, _ ports.PublishRequest) mo.Result[ports.PublishReceipt] {
	f.calls++
	if f.err != nil {
		return shared.Err[ports.PublishReceipt](f.err)
	}
	return shared.Ok(ports.PublishReceipt{Publisher: f.name, Reference: "ref-" + f.name})
}

// ---------- Helpers for building findings ----------

func mkFinding(file string, sev shared.Severity, source finding.ScannerName) finding.Finding {
	loc, err := finding.NewLocation(finding.LocationInput{File: file, StartLine: 1}).Get()
	if err != nil {
		panic(err)
	}
	f, err := finding.New(finding.NewFindingInput{
		RuleID:   "test.rule",
		Severity: sev,
		Location: loc,
		Message:  "x",
		Source:   source,
		Snippet:  file + ":" + sev.String(),
	}).Get()
	if err != nil {
		panic(err)
	}
	return f
}

func mkRevision() scan.Revision {
	r, err := scan.NewRevision("deadbeef", "main").Get()
	if err != nil {
		panic(err)
	}
	return r
}
