// Package markdown renders Cortex scan results as GitHub-flavored Markdown.
// The output is suitable for GitHub Job Summaries, PR comments, and CLI display.
package markdown

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/gate"
	"github.com/vektcore/cortex/internal/domain/scan"
	"github.com/vektcore/cortex/internal/domain/shared"
)

const maxFindingsPerSeverity = 20

// Reporter renders scan results as Markdown.
type Reporter struct{}

// New returns a Reporter. The zero value is also valid.
func New() *Reporter { return &Reporter{} }

// Report writes a Markdown summary to w.
func (r *Reporter) Report(
	w io.Writer,
	s scan.Scan,
	findings []finding.Finding,
	verdict gate.Verdict,
) error {
	return render(w, s, findings, verdict)
}

func render(w io.Writer, s scan.Scan, findings []finding.Finding, verdict gate.Verdict) error {
	p := func(format string, args ...interface{}) {
		fmt.Fprintf(w, format+"\n", args...)
	}

	// Header
	p("# Cortex Security Scan Report")
	p("")
	p("| Field | Value |")
	p("|---|---|")
	p("| **Scan ID** | `%s` |", s.ID())
	p("| **Branch** | `%s` |", orEmpty(s.Revision().Branch(), "—"))
	p("| **Commit** | `%s` |", trunc(s.Revision().Commit(), 8))
	p("| **Date** | %s |", time.Now().UTC().Format("2006-01-02 15:04 UTC"))
	p("| **Total findings** | %d |", len(findings))
	p("")

	// Gate verdict
	if verdict.Passed() {
		p("## ✅ Quality Gate: PASSED")
	} else {
		p("## ❌ Quality Gate: FAILED")
		p("")
		p("### Violations")
		p("")
		p("| Rule | Severity | Count |")
		p("|---|---|---|")
		for _, v := range verdict.Violations() {
			p("| `%s` | — | %d |", v.Rule().Name(), v.Count())
		}
	}
	p("")

	if len(findings) == 0 {
		p("*No findings.*")
		return nil
	}

	// Group by severity
	bySev := groupBySeverity(findings)

	p("## Findings (%d total)", len(findings))
	p("")

	for _, sev := range []shared.Severity{
		shared.SeverityCritical,
		shared.SeverityHigh,
		shared.SeverityMedium,
		shared.SeverityLow,
		shared.SeverityInfo,
	} {
		fs := bySev[sev]
		if len(fs) == 0 {
			continue
		}
		p("### %s (%d)", strings.Title(sev.String()), len(fs)) //nolint:staticcheck
		p("")
		p("| File | Line | Rule | Message |")
		p("|---|---|---|---|")
		shown := fs
		if len(shown) > maxFindingsPerSeverity {
			shown = fs[:maxFindingsPerSeverity]
		}
		for _, f := range shown {
			loc := f.Location()
			msg := trunc(f.Message().String(), 80)
			p("| `%s` | %d | `%s` | %s |",
				loc.File(), loc.StartLine(), f.RuleID(), msg)
		}
		if len(fs) > maxFindingsPerSeverity {
			p("")
			p("*… and %d more %s findings.*", len(fs)-maxFindingsPerSeverity, sev)
		}
		p("")
	}

	return nil
}

func groupBySeverity(findings []finding.Finding) map[shared.Severity][]finding.Finding {
	m := make(map[shared.Severity][]finding.Finding)
	for _, f := range findings {
		m[f.Severity()] = append(m[f.Severity()], f)
	}
	return m
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func orEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
