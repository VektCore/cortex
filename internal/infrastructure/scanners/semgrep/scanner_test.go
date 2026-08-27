package semgrep_test

import (
	"context"
	"testing"

	"github.com/samber/mo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/infrastructure/scanners/semgrep"
)

// ---------- Fakes ----------

// nopCodec is a ports.SarifCodec that is never called in tests where the
// subprocess itself fails before SARIF is produced.
type nopCodec struct{}

func (nopCodec) Parse(_ []byte) mo.Result[[]finding.Finding] {
	return shared.Ok[[]finding.Finding](nil)
}
func (nopCodec) Write(_ []finding.Finding, _ ports.SarifMetadata) mo.Result[[]byte] {
	return shared.Ok[[]byte](nil)
}
func (nopCodec) Merge(_ [][]byte) mo.Result[[]byte] {
	return shared.Ok[[]byte](nil)
}

// ---------- Tests ----------

func TestSemgrepScanner_Name(t *testing.T) {
	t.Parallel()
	sc := semgrep.New(nopCodec{}, "")
	assert.Equal(t, finding.ScannerName("semgrep"), sc.Name())
}

func TestSemgrepScanner_SupportedLanguages(t *testing.T) {
	t.Parallel()
	sc := semgrep.New(nopCodec{}, "")
	langs := sc.SupportedLanguages()
	assert.Contains(t, langs, shared.LanguagePython)
	assert.Contains(t, langs, shared.LanguageGo)
	assert.Contains(t, langs, shared.LanguageCSharp)
	assert.Contains(t, langs, shared.LanguageJava)
	assert.Contains(t, langs, shared.LanguageJavaScript)
	assert.Contains(t, langs, shared.LanguageTypeScript)
}

func TestSemgrepScanner_Available_NonExistentBinary(t *testing.T) {
	t.Parallel()
	sc := semgrep.New(nopCodec{}, "/tmp/cortex-no-such-binary")
	assert.False(t, sc.Available(context.Background()))
}

func TestSemgrepScanner_Scan_BinaryNotFound(t *testing.T) {
	t.Parallel()
	sc := semgrep.New(nopCodec{}, "/tmp/cortex-no-such-binary")
	_, err := sc.Scan(context.Background(), ports.ScanRequest{TargetPath: "."}).Get()
	require.Error(t, err, "scan must fail when binary is not present")
}

func TestSemgrepScanner_Scan_NonSARIFOutput(t *testing.T) {
	t.Parallel()
	// "echo" exists everywhere and produces non-SARIF stdout — useful for
	// testing the invalid-output path without needing semgrep installed.
	sc := semgrep.New(nopCodec{}, "echo")
	_, err := sc.Scan(context.Background(), ports.ScanRequest{TargetPath: "."}).Get()
	require.Error(t, err, "non-SARIF output must be rejected")
	assert.Contains(t, err.Error(), "invalid SARIF")
}

// Note: tests that actually invoke the semgrep binary live in
// test/e2e/semgrep_test.go behind //go:build e2e.
