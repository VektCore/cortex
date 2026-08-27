package gitleaks_test

import (
	"context"
	"testing"

	"github.com/samber/mo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/infrastructure/scanners/gitleaks"
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

func TestGitleaksScanner_Name(t *testing.T) {
	t.Parallel()
	sc := gitleaks.New(nopCodec{}, "")
	assert.Equal(t, finding.ScannerName("gitleaks"), sc.Name())
}

func TestGitleaksScanner_SupportedLanguages(t *testing.T) {
	t.Parallel()
	sc := gitleaks.New(nopCodec{}, "")
	langs := sc.SupportedLanguages()
	assert.Contains(t, langs, shared.LanguagePython)
	assert.Contains(t, langs, shared.LanguageJavaScript)
	assert.Contains(t, langs, shared.LanguageTypeScript)
	assert.Contains(t, langs, shared.LanguageJava)
	assert.Contains(t, langs, shared.LanguageGo)
	assert.Contains(t, langs, shared.LanguageCSharp)
}

func TestGitleaksScanner_Available_NonExistentBinary(t *testing.T) {
	t.Parallel()
	sc := gitleaks.New(nopCodec{}, "/tmp/no-binary")
	assert.False(t, sc.Available(context.Background()))
}

func TestGitleaksScanner_Scan_BinaryNotFound(t *testing.T) {
	t.Parallel()
	sc := gitleaks.New(nopCodec{}, "/tmp/no-binary")
	_, err := sc.Scan(context.Background(), ports.ScanRequest{TargetPath: "."}).Get()
	require.Error(t, err, "scan must fail when binary is not present")
}
