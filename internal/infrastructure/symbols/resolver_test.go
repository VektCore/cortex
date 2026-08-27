package symbols_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/infrastructure/symbols"
)

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
}

func TestResolve_AcrossLanguages(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write(t, dir, "a.py", "import os\n\n\ndef get_user(uid):\n    return uid\n")
	write(t, dir, "b.js", "const x = 1;\n\nasync function fetchData(url) {\n  return url;\n}\n")
	write(t, dir, "c.go", "package main\n\nfunc (s *Server) handleLogin(w, r) {\n\treturn\n}\n")
	write(t, dir, "d.cs", "namespace X {\n  public class Auth {\n    public string Encrypt(string s) {\n      return s;\n    }\n  }\n}\n")

	cases := []struct {
		file string
		line int
		want string
	}{
		{"a.py", 5, "get_user"},
		{"b.js", 4, "fetchData"},
		{"c.go", 4, "handleLogin"},
		{"d.cs", 4, "Encrypt"},
	}

	resolver := symbols.New()
	for _, c := range cases {
		got, ok := resolver.Resolve(context.Background(), dir, c.file, c.line).Get()
		require.True(t, ok, "%s:%d should resolve", c.file, c.line)
		assert.Equal(t, c.want, got)
	}
}

func TestResolve_UnknownRatherThanWrong(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write(t, dir, "top.py", "SECRET = \"abc\"\n")

	resolver := symbols.New()

	// Above every declaration: no symbol, not a guess.
	_, ok := resolver.Resolve(context.Background(), dir, "top.py", 1).Get()
	assert.False(t, ok, "a line outside any declaration must resolve to nothing")

	// A file that does not exist must not error, just decline.
	_, ok = resolver.Resolve(context.Background(), dir, "missing.py", 3).Get()
	assert.False(t, ok)

	// A line past the end of the file still resolves against the last
	// declaration rather than panicking.
	write(t, dir, "short.py", "def only():\n    pass\n")
	got, ok := resolver.Resolve(context.Background(), dir, "short.py", 99).Get()
	require.True(t, ok)
	assert.Equal(t, "only", got)
}

func TestResolve_IgnoresComments(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write(t, dir, "x.py", "def real_one():\n    pass\n\n\n# def commented_out():\n    value = 1\n")

	got, ok := symbols.New().Resolve(context.Background(), dir, "x.py", 6).Get()
	require.True(t, ok)
	assert.Equal(t, "real_one", got, "a commented declaration is not a declaration")
}
