package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The exit codes are the public contract with CI: a pipeline blocks a merge
// because cortex returned 1, and distinguishes "the gate failed" from "the
// scanner broke" by the number alone. Nothing else in the suite covers that
// mapping, so a refactor of the error paths could silently turn a failing gate
// into a passing build.

// sarifOneHighFinding is a minimal SARIF v2.1.0 document with a single
// "error"-level result, which Cortex maps to high severity.
const sarifOneHighFinding = `{
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "semgrep" } },
      "results": [
        {
          "ruleId": "python.lang.security.audit.sql-injection",
          "level": "error",
          "message": { "text": "SQL injection: query built from user input" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "app/db.py" },
                "region": { "startLine": 42, "endLine": 42 }
              }
            }
          ]
        }
      ]
    }
  ]
}`

// configGating returns a config whose only gate rule fires at the given
// severity. State is off so the tests never write a state file.
func configGating(severity string) string {
	return `version: "1"
state:
  enabled: false
publishers:
  filesystem:
    enabled: false
gate:
  rules:
    - name: gate-under-test
      severity: ` + severity + `
      threshold: ">=1"
`
}

// writeFixture drops content into a temp file and returns its path.
func writeFixture(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestExecute_ExitCodes(t *testing.T) {
	dir := t.TempDir()

	sarif := writeFixture(t, dir, "scan.sarif", sarifOneHighFinding)
	failingCfg := writeFixture(t, dir, "fails.yaml", configGating("high"))
	passingCfg := writeFixture(t, dir, "passes.yaml", configGating("critical"))
	brokenCfg := writeFixture(t, dir, "broken.yaml", "gate:\n  rules:\n  - name: [unclosed\n")

	tests := []struct {
		name string
		args []string
		want int
		why  string
	}{
		{
			name: "gate failure is exit 1, not an error",
			args: []string{"verify", sarif, "-c", failingCfg},
			want: ExitGateFailed,
			why:  "a high finding against a rule that fires at high must block the merge",
		},
		{
			name: "gate passing is exit 0",
			args: []string{"verify", sarif, "-c", passingCfg},
			want: ExitOK,
			why:  "the only rule fires at critical and the finding is high",
		},
		{
			name: "unreadable config is exit 2",
			args: []string{"verify", sarif, "-c", brokenCfg},
			want: ExitConfigError,
			why:  "a broken config must be distinguishable from a failing gate",
		},
		{
			name: "missing SARIF is exit 2",
			args: []string{"verify", filepath.Join(dir, "does-not-exist.sarif"), "-c", passingCfg},
			want: ExitConfigError,
			why:  "nothing to evaluate is an input problem, never a silent pass",
		},
		{
			name: "unknown command is exit 99",
			args: []string{"definitely-not-a-command"},
			want: ExitInternalError,
			why:  "an unmapped failure must not masquerade as a gate verdict",
		},
		{
			name: "version is exit 0",
			args: []string{"version"},
			want: ExitOK,
			why:  "a query command never gates anything",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Execute(context.Background(), tc.args)
			assert.Equal(t, tc.want, got, tc.why)
		})
	}
}

// The numbers themselves are the contract — CI pipelines and the composite
// action branch on them, so they cannot be renumbered silently.
func TestExitCodeValues(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 0, ExitOK)
	assert.Equal(t, 1, ExitGateFailed)
	assert.Equal(t, 2, ExitConfigError)
	assert.Equal(t, 3, ExitScannerError)
	assert.Equal(t, 4, ExitPublisherError)
	assert.Equal(t, 99, ExitInternalError)
}

// A scan whose target does not exist must report a scanner error (3), which is
// what tells CI "the tooling broke" rather than "your code is bad".
func TestExecute_ScanOfMissingTargetIsScannerError(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFixture(t, dir, "cfg.yaml", `version: "1"
state:
  enabled: false
publishers:
  filesystem:
    enabled: false
scanners:
  semgrep:
    enabled: false
  bandit:
    enabled: false
  gosec:
    enabled: false
  gitleaks:
    enabled: false
  osv:
    enabled: false
`)

	got := Execute(context.Background(), []string{
		"scan", filepath.Join(dir, "no-such-directory"),
		"-c", cfg, "--output", filepath.Join(dir, "out"), "--quiet",
	})

	assert.Equal(t, ExitScannerError, got,
		"a target that cannot be analysed is a scanner error, not a gate verdict")
}
