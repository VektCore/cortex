package shared

import (
	"strings"

	"github.com/samber/mo"
)

// Language is a value object enumerating every programming language Cortex
// can target. Adding a new language requires:
//
//  1. Appending a constant here.
//  2. Extending ParseLanguage.
//  3. Wiring at least one Scanner adapter that supports it.
//  4. Adding a fixture under test/fixtures/kassandra-sast-demo/<lang>.
type Language string

const (
	LanguageUnknown    Language = ""
	LanguagePython     Language = "python"
	LanguageJavaScript Language = "javascript"
	LanguageTypeScript Language = "typescript"
	LanguageJava       Language = "java"
	LanguageGo         Language = "go"
	LanguageCSharp     Language = "csharp"
)

// AllLanguages returns the deterministic ordered set of supported languages.
// The order matters for tests and report rendering.
func AllLanguages() []Language {
	return []Language{
		LanguagePython,
		LanguageJavaScript,
		LanguageTypeScript,
		LanguageJava,
		LanguageGo,
		LanguageCSharp,
	}
}

// String implements fmt.Stringer.
func (l Language) String() string { return string(l) }

// IsKnown returns true if the language is part of AllLanguages.
func (l Language) IsKnown() bool {
	for _, k := range AllLanguages() {
		if k == l {
			return true
		}
	}
	return false
}

// ParseLanguage normalizes free-form input (CLI flags, YAML, scanner output)
// into a Language. Accepts common aliases.
func ParseLanguage(raw string) mo.Result[Language] {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "python", "py":
		return Ok(LanguagePython)
	case "javascript", "js", "node":
		return Ok(LanguageJavaScript)
	case "typescript", "ts":
		return Ok(LanguageTypeScript)
	case "java":
		return Ok(LanguageJava)
	case "go", "golang":
		return Ok(LanguageGo)
	case "csharp", "c#", "dotnet", "cs":
		return Ok(LanguageCSharp)
	default:
		return Err[Language](NewDomainError(
			"LANGUAGE_UNKNOWN",
			"unknown language: "+raw,
		))
	}
}
