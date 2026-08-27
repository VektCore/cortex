package shared_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/domain/shared"
)

func TestParseLanguage_Aliases(t *testing.T) {
	t.Parallel()
	cases := map[string]shared.Language{
		"python":     shared.LanguagePython,
		"PY":         shared.LanguagePython,
		"javascript": shared.LanguageJavaScript,
		"node":       shared.LanguageJavaScript,
		"ts":         shared.LanguageTypeScript,
		"java":       shared.LanguageJava,
		"go":         shared.LanguageGo,
		"golang":     shared.LanguageGo,
		"c#":         shared.LanguageCSharp,
		"dotnet":     shared.LanguageCSharp,
	}
	for raw, want := range cases {
		r := shared.ParseLanguage(raw)
		got, err := r.Get()
		require.NoError(t, err, "input=%q", raw)
		assert.Equal(t, want, got, "input=%q", raw)
	}
}

func TestParseLanguage_Unknown(t *testing.T) {
	t.Parallel()
	r := shared.ParseLanguage("cobol")
	_, err := r.Get()
	assert.Error(t, err)
}

func TestLanguage_IsKnown(t *testing.T) {
	t.Parallel()
	for _, l := range shared.AllLanguages() {
		assert.True(t, l.IsKnown(), "%s should be known", l)
	}
	assert.False(t, shared.Language("klingon").IsKnown())
}
