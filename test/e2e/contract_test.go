//go:build e2e

// The fixture contract test.
//
// test/fixtures/README.md declares, per file, which weakness Cortex is expected
// to find and with which CWE. That table is the product's contract: this test
// reads it and fails when a declared weakness stops being detected — which is
// exactly what happens when a scanner adapter, the SARIF parser or the CWE
// tables regress.
//
//	make test-e2e
//
// Requires the scanners on PATH (semgrep, bandit, gitleaks, eslint).
package e2e_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/infrastructure/sarif"
)

// contractRow is one line of the table in test/fixtures/README.md.
type contractRow struct {
	file string
	cwe  string
	what string
}

// rowPattern captures "| `python/database.py` | SQL Injection | CWE-89 | CRITICAL |".
var rowPattern = regexp.MustCompile(
	"^\\|\\s*`([^`]+)`\\s*\\|\\s*([^|]+?)\\s*\\|\\s*(CWE-\\d+|many|multiple)\\s*\\|",
)

func TestFixtureContract(t *testing.T) {
	root := repoRoot(t)
	fixture := filepath.Join(root, "test", "fixtures", "kassandra-sast-demo")

	rows := parseContract(t, filepath.Join(root, "test", "fixtures", "README.md"))
	require.NotEmpty(t, rows, "the contract table must be readable")

	findings := runScan(t, root, fixture)
	require.NotEmpty(t, findings, "the scan must produce findings")

	byFile := make(map[string][]finding.Finding, len(findings))
	for _, f := range findings {
		byFile[f.Location().File()] = append(byFile[f.Location().File()], f)
	}

	for _, row := range rows {
		t.Run(row.file, func(t *testing.T) {
			inFile := byFile[row.file]
			require.NotEmpty(t, inFile,
				"%s declares %q but no finding was reported there", row.file, row.what)

			// Rows whose CWE column says "many"/"multiple" only promise that
			// something is found there, which the assertion above covers.
			if row.cwe == "many" || row.cwe == "multiple" {
				return
			}

			assert.True(t, hasCWE(inFile, row.cwe),
				"%s declares %s (%s); reported CWEs there: %v",
				row.file, row.cwe, row.what, cwesOf(inFile))
		})
	}
}

func hasCWE(findings []finding.Finding, want string) bool {
	for _, f := range findings {
		if cwe, ok := f.CWE().Get(); ok && cwe.String() == want {
			return true
		}
	}
	return false
}

func cwesOf(findings []finding.Finding) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		cwe, ok := f.CWE().Get()
		if !ok {
			continue
		}
		if _, dup := seen[cwe.String()]; dup {
			continue
		}
		seen[cwe.String()] = struct{}{}
		out = append(out, cwe.String())
	}
	return out
}

func parseContract(t *testing.T, path string) []contractRow {
	t.Helper()

	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	var rows []contractRow
	for _, line := range strings.Split(string(raw), "\n") {
		match := rowPattern.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		rows = append(rows, contractRow{
			file: match[1],
			what: match[2],
			cwe:  match[3],
		})
	}
	return rows
}

// runScan invokes the real CLI so the test covers the same path a user takes,
// then parses the canonical SARIF it produced.
func runScan(t *testing.T, root, fixture string) []finding.Finding {
	t.Helper()

	out := t.TempDir()

	cmd := exec.Command("go", "run", "./cmd/cortex",
		"scan", fixture, "--output", out, "--quiet")
	cmd.Dir = root
	combined, err := cmd.CombinedOutput()
	require.NoError(t, err, "cortex scan failed:\n%s", combined)

	data, err := os.ReadFile(filepath.Join(out, "scan.sarif"))
	require.NoError(t, err)

	findings, err := sarif.New().Parse(data).Get()
	require.NoError(t, err)
	return findings
}

func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	require.NoError(t, err)

	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "go.mod not found above %s", dir)
		dir = parent
	}
}
