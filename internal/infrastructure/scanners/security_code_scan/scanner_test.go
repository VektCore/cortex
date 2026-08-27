package security_code_scan_test

import (
	"context"
	"testing"

	"github.com/samber/mo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/infrastructure/scanners/security_code_scan"
)

// ---------- Fakes ----------

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

func TestSecurityCodeScanScanner_Name(t *testing.T) {
	t.Parallel()
	sc := security_code_scan.New(nopCodec{}, "")
	assert.Equal(t, finding.ScannerName("security-code-scan"), sc.Name())
}

func TestSecurityCodeScanScanner_SupportedLanguages(t *testing.T) {
	t.Parallel()
	sc := security_code_scan.New(nopCodec{}, "")
	langs := sc.SupportedLanguages()
	assert.Contains(t, langs, shared.LanguageCSharp)
	assert.Len(t, langs, 1)
}

func TestSecurityCodeScanScanner_Available_NonExistentBinary(t *testing.T) {
	t.Parallel()
	sc := security_code_scan.New(nopCodec{}, "/tmp/cortex-no-such-binary")
	assert.False(t, sc.Available(context.Background()))
}

func TestSecurityCodeScanScanner_Scan_BinaryNotFound(t *testing.T) {
	t.Parallel()
	sc := security_code_scan.New(nopCodec{}, "/tmp/cortex-no-such-binary")
	_, err := sc.Scan(context.Background(), ports.ScanRequest{TargetPath: "."}).Get()
	require.Error(t, err, "scan must fail when binary is not present")
}
