//go:build e2e

package e2e_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/shared"
	infrasarif "github.com/vektcore/cortex/internal/infrastructure/sarif"
	"github.com/vektcore/cortex/internal/infrastructure/scanners/semgrep"
)

// semgrepAvailable returns true when semgrep is in PATH.
func semgrepAvailable(t *testing.T) bool {
	t.Helper()
	_, err := exec.LookPath("semgrep")
	return err == nil
}

// fixturePath returns the absolute path to the test fixture directory.
func fixturePath(t *testing.T, rel string) string {
	t.Helper()
	// Walk up from the test file location to reach the repo root.
	abs, err := filepath.Abs(filepath.Join("..", "..", rel))
	require.NoError(t, err)
	_, err = os.Stat(abs)
	require.NoError(t, err, "fixture path must exist: %s", abs)
	return abs
}

func TestE2E_Semgrep_Python_DetectsExpectedCWEs(t *testing.T) {
	if !semgrepAvailable(t) {
		t.Skip("semgrep not installed — skipping E2E test")
	}

	fixture := fixturePath(t, "test/fixtures/kassandra-sast-demo/python")
	codec := infrasarif.New()
	sc := semgrep.New(codec, "")

	require.True(t, sc.Available(context.Background()))

	out, err := sc.Scan(context.Background(), ports.ScanRequest{
		TargetPath: fixture,
		Options: map[string]string{
			"config": "p/python",
		},
	}).Get()
	require.NoError(t, err)

	// The Python fixture contains intentional SQL injection (CWE-89).
	// We do not assert exact count — that is fragile as rules evolve.
	assert.NotEmpty(t, out.Findings, "expect at least one finding in the Python fixture")
	assert.NotEmpty(t, out.RawSARIF, "raw SARIF must be populated")

	// Verify at least one HIGH or CRITICAL finding exists
	highOrCritical := 0
	for _, f := range out.Findings {
		if f.Severity().AtLeast(shared.SeverityHigh) {
			highOrCritical++
		}
	}
	assert.Greater(t, highOrCritical, 0, "expect at least one HIGH+ finding in Python security fixture")

	t.Logf("E2E: semgrep found %d findings (%d high+) in Python fixture",
		len(out.Findings), highOrCritical)
}

func TestE2E_Semgrep_RoundTripSARIF(t *testing.T) {
	if !semgrepAvailable(t) {
		t.Skip("semgrep not installed — skipping E2E test")
	}

	fixture := fixturePath(t, "test/fixtures/kassandra-sast-demo/python")
	codec := infrasarif.New()
	sc := semgrep.New(codec, "")

	out, err := sc.Scan(context.Background(), ports.ScanRequest{
		TargetPath: fixture,
	}).Get()
	require.NoError(t, err)

	// Round-trip: parse the raw SARIF and ensure we get back the same findings.
	reparsed, parseErr := codec.Parse(out.RawSARIF).Get()
	require.NoError(t, parseErr)
	assert.Equal(t, len(out.Findings), len(reparsed),
		"round-trip parse must recover the same finding count")
}
