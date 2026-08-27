package scanners_test

import (
	"context"
	"testing"

	"github.com/samber/mo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/infrastructure/scanners"
)

// ---------- Fakes ----------

type stubScanner struct {
	name  finding.ScannerName
	langs []shared.Language
}

func (s *stubScanner) Name() finding.ScannerName             { return s.name }
func (s *stubScanner) SupportedLanguages() []shared.Language { return s.langs }
func (s *stubScanner) Available(_ context.Context) bool      { return true }
func (s *stubScanner) Scan(_ context.Context, _ ports.ScanRequest) mo.Result[ports.ScanOutput] {
	return shared.Ok(ports.ScanOutput{Scanner: s.name})
}

// ---------- Tests ----------

func TestRegistry_RegisterAndGet(t *testing.T) {
	t.Parallel()
	r := scanners.New()
	sc := &stubScanner{name: "semgrep", langs: []shared.Language{shared.LanguagePython}}
	r.Register(sc)

	got, ok := r.Get("semgrep").Get()
	require.True(t, ok)
	assert.Equal(t, finding.ScannerName("semgrep"), got.Name())
}

func TestRegistry_Get_Missing(t *testing.T) {
	t.Parallel()
	r := scanners.New()
	_, ok := r.Get("nonexistent").Get()
	assert.False(t, ok)
}

func TestRegistry_All(t *testing.T) {
	t.Parallel()
	r := scanners.New()
	r.Register(&stubScanner{name: "a"})
	r.Register(&stubScanner{name: "b"})

	all := r.All()
	assert.Len(t, all, 2)
}

func TestRegistry_ForLanguage(t *testing.T) {
	t.Parallel()
	r := scanners.New()
	r.Register(&stubScanner{name: "python-only", langs: []shared.Language{shared.LanguagePython}})
	r.Register(&stubScanner{name: "go-only", langs: []shared.Language{shared.LanguageGo}})
	r.Register(&stubScanner{name: "multi", langs: []shared.Language{shared.LanguagePython, shared.LanguageGo}})

	pyScans := r.ForLanguage(shared.LanguagePython)
	assert.Len(t, pyScans, 2, "python-only and multi should match")

	goScans := r.ForLanguage(shared.LanguageGo)
	assert.Len(t, goScans, 2, "go-only and multi should match")

	jsScans := r.ForLanguage(shared.LanguageJavaScript)
	assert.Empty(t, jsScans)
}

func TestRegistry_ForLanguages_Deduplicated(t *testing.T) {
	t.Parallel()
	r := scanners.New()
	r.Register(&stubScanner{
		name:  "multi",
		langs: []shared.Language{shared.LanguagePython, shared.LanguageGo},
	})

	result := r.ForLanguages([]shared.Language{shared.LanguagePython, shared.LanguageGo})
	assert.Len(t, result, 1, "multi-language scanner must appear only once")
}

func TestRegistry_Register_Replaces(t *testing.T) {
	t.Parallel()
	r := scanners.New()
	r.Register(&stubScanner{name: "x", langs: []shared.Language{shared.LanguagePython}})
	r.Register(&stubScanner{name: "x", langs: []shared.Language{shared.LanguageGo}}) // overwrite

	got, ok := r.Get("x").Get()
	require.True(t, ok)
	// The replacement has Go, not Python
	assert.Contains(t, got.SupportedLanguages(), shared.LanguageGo)
	assert.NotContains(t, got.SupportedLanguages(), shared.LanguagePython)
}
