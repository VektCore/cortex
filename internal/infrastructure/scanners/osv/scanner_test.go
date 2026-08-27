package osv_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/infrastructure/sarif"
	"github.com/vektcore/cortex/internal/infrastructure/scanners/osv"
)

func TestScanner_Identity(t *testing.T) {
	t.Parallel()

	s := osv.New(sarif.New(), "")

	assert.Equal(t, "osv", string(s.Name()))
	// Dependency manifests exist for every language, and osv-scanner decides
	// what it recognises by looking at the files.
	assert.Len(t, s.SupportedLanguages(), 6)
	assert.Contains(t, s.SupportedLanguages(), shared.LanguageGo)
	assert.Contains(t, s.SupportedLanguages(), shared.LanguageCSharp)
}

func TestScanner_UnavailableBinary(t *testing.T) {
	t.Parallel()

	s := osv.New(sarif.New(), "definitely-not-a-real-binary-osv")
	assert.False(t, s.Available(context.Background()))

	_, err := s.Scan(context.Background(), ports.ScanRequest{TargetPath: "."}).Get()
	require.Error(t, err, "a missing binary must be an error the use case can isolate")
	assert.Contains(t, err.Error(), "osv")
}

func TestScanner_NonSARIFOutputIsAnError(t *testing.T) {
	t.Parallel()

	// "echo" exits 0 and prints something that is not SARIF: the adapter must
	// not pass that off as an empty result set.
	s := osv.New(sarif.New(), "echo")

	_, err := s.Scan(context.Background(), ports.ScanRequest{TargetPath: "."}).Get()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SARIF")
}

// osv-scanner exits 128 when it finds no manifest it understands. Cortex used
// to report that as a scanner failure, which marked osv broken on every
// repository without a dependency file it can read.
func TestScanner_NoPackagesFoundIsNotAFailure(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("the stub is a shell script")
	}

	stub := filepath.Join(t.TempDir(), "osv-stub")
	script := "#!/bin/sh\n" +
		"echo 'No package sources found, --help for usage information.' >&2\n" +
		"exit 128\n"
	require.NoError(t, os.WriteFile(stub, []byte(script), 0o755))

	out, err := osv.New(sarif.New(), stub).
		Scan(context.Background(), ports.ScanRequest{TargetPath: "."}).Get()

	require.NoError(t, err, "nothing to scan is an empty result, not a failure")
	assert.Empty(t, out.Findings)
	assert.Empty(t, out.RawSARIF, "no document was produced, so none is forwarded")
}

// A non-zero exit that is not 128 still has to surface.
func TestScanner_OtherFailuresStillError(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("the stub is a shell script")
	}

	stub := filepath.Join(t.TempDir(), "osv-stub")
	require.NoError(t, os.WriteFile(stub,
		[]byte("#!/bin/sh\necho 'database unreachable' >&2\nexit 2\n"), 0o755))

	_, err := osv.New(sarif.New(), stub).
		Scan(context.Background(), ports.ScanRequest{TargetPath: "."}).Get()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "database unreachable")
}
