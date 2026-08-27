package finding_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

func mkFindingAt(t *testing.T, file string) finding.Finding {
	t.Helper()

	loc, err := finding.NewLocation(finding.LocationInput{File: file, StartLine: 3}).Get()
	require.NoError(t, err)

	f, err := finding.New(finding.NewFindingInput{
		RuleID:   "B608",
		Severity: shared.SeverityHigh,
		Location: loc,
		Message:  "sqli",
		Source:   "bandit",
		Snippet:  "query = 'SELECT ' + x",
	}).Get()
	require.NoError(t, err)

	return f
}

func TestNormalizePath_EveryFormAScannerEmits(t *testing.T) {
	t.Parallel()

	roots := []string{"test/fixtures/demo", "/abs/repo", "/tmp/cortex-clone-9"}

	cases := map[string]string{
		"test/fixtures/demo/python/a.py":  "python/a.py",
		"/abs/repo/python/a.py":           "python/a.py",
		"file:///abs/repo/python/a.py":    "python/a.py",
		"/tmp/cortex-clone-9/src/main.go": "src/main.go",
		"./python/a.py":                   "python/a.py",
		"unrelated/x.py":                  "unrelated/x.py",
	}

	for in, want := range cases {
		assert.Equal(t, want, finding.NormalizePath(in, roots), "input %q", in)
	}
}

func TestRelativize_RecomputesFingerprint(t *testing.T) {
	t.Parallel()

	absolute := mkFindingAt(t, "/abs/repo/python/a.py")
	relative := mkFindingAt(t, "python/a.py")

	out := finding.Relativize([]finding.Finding{absolute}, []string{"/abs/repo"})
	require.Len(t, out, 1)

	assert.Equal(t, "python/a.py", out[0].Location().File())
	assert.Equal(t, relative.Fingerprint(), out[0].Fingerprint(),
		"the same finding must fingerprint identically however it was reported")
}

func TestPathMatches_PrefixGlobAndSegment(t *testing.T) {
	t.Parallel()

	assert.True(t, finding.PathMatches("tests/test_api.py", "tests/"))
	assert.True(t, finding.PathMatches("services/api/tests/test_x.py", "tests/"))
	assert.True(t, finding.PathMatches("services/api/tests/test_x.py", "services/*/tests/*"))
	assert.True(t, finding.PathMatches("web/node_modules/lib/index.js", "node_modules"))
	assert.False(t, finding.PathMatches("services/api/app.py", "tests/"))
	assert.False(t, finding.PathMatches("services/api/app.py", ""))
}

func TestExcludePaths(t *testing.T) {
	t.Parallel()

	in := []finding.Finding{
		mkFindingAt(t, "app/main.py"),
		mkFindingAt(t, "web/node_modules/lib/index.js"),
		mkFindingAt(t, "tests/test_main.py"),
	}

	out := finding.ExcludePaths(in, []string{"node_modules/", "tests/"})
	require.Len(t, out, 1)
	assert.Equal(t, "app/main.py", out[0].Location().File())
}
