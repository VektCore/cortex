package language_detection

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// Detector implements ports.LanguageDetector by walking the filesystem.
// Detection uses two signals:
//  1. File extensions (.py, .go, .java, .cs, .js, .ts)
//  2. Manifest files (go.mod, pyproject.toml, package.json, pom.xml, *.csproj)
//
// Results are deduplicated and returned in AllLanguages() order.
type Detector struct{}

// New returns a ready Detector. The zero value is also valid.
func New() *Detector { return &Detector{} }

// Ensure compile-time interface satisfaction.
var _ ports.LanguageDetector = (*Detector)(nil)

// extension → Language
var extLanguage = map[string]shared.Language{
	".py":   shared.LanguagePython,
	".go":   shared.LanguageGo,
	".java": shared.LanguageJava,
	".cs":   shared.LanguageCSharp,
	".js":   shared.LanguageJavaScript,
	".jsx":  shared.LanguageJavaScript,
	".mjs":  shared.LanguageJavaScript,
	".cjs":  shared.LanguageJavaScript,
	".ts":   shared.LanguageTypeScript,
	".tsx":  shared.LanguageTypeScript,
}

// manifest filename → Language (exact base name match)
var manifestLanguage = map[string]shared.Language{
	"go.mod":           shared.LanguageGo,
	"pyproject.toml":   shared.LanguagePython,
	"setup.py":         shared.LanguagePython,
	"requirements.txt": shared.LanguagePython,
	"package.json":     shared.LanguageJavaScript,
	"pom.xml":          shared.LanguageJava,
	"build.gradle":     shared.LanguageJava,
	"build.gradle.kts": shared.LanguageJava,
}

// directories that are always skipped
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
	".venv": true, "venv": true, "__pycache__": true,
	"target": true, "build": true, "dist": true,
	"bin": true, "obj": true, ".idea": true, ".vs": true,
}

// skipped reports whether a directory is one Cortex never walks or one the
// caller excluded. Exclusions are matched against both the path relative to the
// scan root and the bare directory name, so "node_modules" and
// "web/node_modules" both work.
func skipped(root, dir, name string, exclude []string) bool {
	if skipDirs[name] {
		return true
	}
	rel, _ := filepath.Rel(root, dir)
	for _, pattern := range exclude {
		if matched, _ := filepath.Match(pattern, rel); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, name); matched {
			return true
		}
	}
	return false
}

// languagesOf reports which languages a file name implies: by extension, by
// being a known manifest, or by a project-file suffix.
func languagesOf(name string) []shared.Language {
	lower := strings.ToLower(name)
	out := make([]shared.Language, 0, 2)

	if lang, ok := extLanguage[strings.ToLower(filepath.Ext(name))]; ok {
		out = append(out, lang)
	}
	if lang, ok := manifestLanguage[lower]; ok {
		out = append(out, lang)
	}
	if strings.HasSuffix(lower, ".csproj") || strings.HasSuffix(lower, ".sln") {
		out = append(out, shared.LanguageCSharp)
	}
	return out
}

// Detect walks path and returns every language found.
// The exclude parameter lists glob patterns relative to path to skip.
func (d *Detector) Detect(
	ctx context.Context,
	path string,
	exclude []string,
) mo.Result[[]shared.Language] {
	seen := make(map[shared.Language]struct{})

	err := filepath.WalkDir(path, func(p string, de fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if de.IsDir() {
			if skipped(path, p, de.Name(), exclude) {
				return fs.SkipDir
			}
			return nil
		}

		for _, lang := range languagesOf(de.Name()) {
			seen[lang] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return shared.Err[[]shared.Language](fmt.Errorf("language detection: %w", err))
	}

	// Return in canonical order so output is deterministic.
	out := make([]shared.Language, 0, len(seen))
	for _, lang := range shared.AllLanguages() {
		if _, ok := seen[lang]; ok {
			out = append(out, lang)
		}
	}
	return shared.Ok(out)
}
