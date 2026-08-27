package finding_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// build is a tiny builder used by every test file in this package.
// It exercises the real public constructor, so a misuse here is also
// a regression in the Finding invariants.
func build(t *testing.T, opts ...func(*finding.NewFindingInput)) finding.Finding {
	t.Helper()
	in := finding.NewFindingInput{
		RuleID:   "semgrep.test.rule",
		Severity: shared.SeverityHigh,
		Location: finding.MustNewLocation(finding.LocationInput{
			File: "src/main.go", StartLine: 10,
		}),
		Message: "test finding",
		Source:  "semgrep",
		Snippet: "if x == nil { panic(\"boom\") }",
	}
	for _, opt := range opts {
		opt(&in)
	}
	r := finding.New(in)
	v, err := r.Get()
	require.NoError(t, err)
	return v
}

func withSeverity(s shared.Severity) func(*finding.NewFindingInput) {
	return func(in *finding.NewFindingInput) { in.Severity = s }
}
func withFile(file string) func(*finding.NewFindingInput) {
	return func(in *finding.NewFindingInput) {
		in.Location = finding.MustNewLocation(finding.LocationInput{File: file, StartLine: 1})
	}
}
func withSnippet(s string) func(*finding.NewFindingInput) {
	return func(in *finding.NewFindingInput) { in.Snippet = s }
}
func withSource(s finding.ScannerName) func(*finding.NewFindingInput) {
	return func(in *finding.NewFindingInput) { in.Source = s }
}
