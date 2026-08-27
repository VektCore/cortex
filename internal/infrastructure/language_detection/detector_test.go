package language_detection_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/domain/shared"
	langdetect "github.com/vektcore/cortex/internal/infrastructure/language_detection"
)

func makeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		full := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
	}
	return root
}

func TestDetector_Python_ByExtension(t *testing.T) {
	t.Parallel()
	d := langdetect.New()
	root := makeTree(t, map[string]string{
		"app/main.py":  "print('hello')",
		"app/utils.py": "",
	})
	langs, err := d.Detect(context.Background(), root, nil).Get()
	require.NoError(t, err)
	assert.Contains(t, langs, shared.LanguagePython)
	assert.Len(t, langs, 1)
}

func TestDetector_Go_ByManifest(t *testing.T) {
	t.Parallel()
	d := langdetect.New()
	root := makeTree(t, map[string]string{
		"go.mod": "module example\ngo 1.22",
	})
	langs, err := d.Detect(context.Background(), root, nil).Get()
	require.NoError(t, err)
	assert.Contains(t, langs, shared.LanguageGo)
}

func TestDetector_TypeScript_ByExtension(t *testing.T) {
	t.Parallel()
	d := langdetect.New()
	root := makeTree(t, map[string]string{
		"src/index.ts": "",
		"src/App.tsx":  "",
	})
	langs, err := d.Detect(context.Background(), root, nil).Get()
	require.NoError(t, err)
	assert.Contains(t, langs, shared.LanguageTypeScript)
	assert.NotContains(t, langs, shared.LanguageJavaScript)
}

func TestDetector_CSharp_ByCsproj(t *testing.T) {
	t.Parallel()
	d := langdetect.New()
	root := makeTree(t, map[string]string{
		"MyApp.csproj": "<Project Sdk=\"Microsoft.NET.Sdk\" />",
	})
	langs, err := d.Detect(context.Background(), root, nil).Get()
	require.NoError(t, err)
	assert.Contains(t, langs, shared.LanguageCSharp)
}

func TestDetector_MultiLanguage(t *testing.T) {
	t.Parallel()
	d := langdetect.New()
	root := makeTree(t, map[string]string{
		"backend/main.go":       "",
		"backend/go.mod":        "",
		"frontend/index.ts":     "",
		"frontend/package.json": "{}",
	})
	langs, err := d.Detect(context.Background(), root, nil).Get()
	require.NoError(t, err)
	assert.Contains(t, langs, shared.LanguageGo)
	assert.Contains(t, langs, shared.LanguageTypeScript)
}

func TestDetector_SkipsNodeModules(t *testing.T) {
	t.Parallel()
	d := langdetect.New()
	root := makeTree(t, map[string]string{
		"src/app.ts":                "",
		"node_modules/dep/index.js": "",
	})
	langs, err := d.Detect(context.Background(), root, nil).Get()
	require.NoError(t, err)
	assert.Contains(t, langs, shared.LanguageTypeScript)
	// node_modules has .js but should be skipped
	assert.NotContains(t, langs, shared.LanguageJavaScript)
}

func TestDetector_EmptyDirectory(t *testing.T) {
	t.Parallel()
	d := langdetect.New()
	root := t.TempDir()
	langs, err := d.Detect(context.Background(), root, nil).Get()
	require.NoError(t, err)
	assert.Empty(t, langs)
}

func TestDetector_CanonicalOrder(t *testing.T) {
	t.Parallel()
	d := langdetect.New()
	root := makeTree(t, map[string]string{
		"main.go":   "",
		"app.py":    "",
		"Main.java": "",
	})
	langs, err := d.Detect(context.Background(), root, nil).Get()
	require.NoError(t, err)
	// Python < Java < Go in AllLanguages() order
	pyIdx, javaIdx, goIdx := -1, -1, -1
	for i, l := range langs {
		switch l {
		case shared.LanguagePython:
			pyIdx = i
		case shared.LanguageJava:
			javaIdx = i
		case shared.LanguageGo:
			goIdx = i
		}
	}
	assert.Less(t, pyIdx, javaIdx)
	assert.Less(t, javaIdx, goIdx)
}
