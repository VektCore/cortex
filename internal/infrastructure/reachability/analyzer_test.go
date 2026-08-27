package reachability_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/infrastructure/reachability"
)

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
}

func TestUnreachableSymbols_CalledVersusOrphan(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write(t, dir, "service.py", `from helpers import build_live

def process(uid):
    return build_live(uid)
`)
	write(t, dir, "helpers.py", `def build_live(uid):
    return "SELECT " + uid


def build_orphan(oid):
    return "SELECT " + oid
`)

	result, err := reachability.New().UnreachableSymbols(context.Background(), dir, []ports.SymbolRef{
		{Symbol: "build_live", File: "helpers.py"},
		{Symbol: "build_orphan", File: "helpers.py"},
	}).Get()
	require.NoError(t, err)

	assert.False(t, result["build_live"], "a symbol someone calls is reachable")
	assert.True(t, result["build_orphan"], "a symbol nothing references is unreachable")
}

func TestUnreachableSymbols_LeavesTheRiskyCasesUnknown(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write(t, dir, "main.py", "def handler(event):\n    return event\n")
	write(t, dir, "lib.py", "def ExportedThing():\n    pass\n\n\ndef run():\n    pass\n")

	result, err := reachability.New().UnreachableSymbols(context.Background(), dir, []ports.SymbolRef{
		// A framework calls a handler by name; an entrypoint file proves nothing.
		{Symbol: "handler", File: "main.py"},
		// An exported symbol may be called from outside the repository.
		{Symbol: "ExportedThing", File: "lib.py"},
		// A name too short or too common to search for.
		{Symbol: "run", File: "lib.py"},
	}).Get()
	require.NoError(t, err)

	for _, symbol := range []string{"handler", "ExportedThing", "run"} {
		_, decided := result[symbol]
		assert.False(t, decided,
			"%s must stay unknown: calling live code dead is the expensive mistake", symbol)
	}
}

func TestUnreachableSymbols_TestOnlyUsageIsInconclusive(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write(t, dir, "helpers.py", "def build_query(uid):\n    return uid\n")
	write(t, dir, "tests/test_helpers.py", "from helpers import build_query\n\n\ndef test_it():\n    assert build_query(1)\n")

	result, err := reachability.New().UnreachableSymbols(context.Background(), dir, []ports.SymbolRef{
		{Symbol: "build_query", File: "helpers.py"},
	}).Get()
	require.NoError(t, err)

	_, decided := result["build_query"]
	assert.False(t, decided,
		"only a test uses it: not production-reachable, but not dead either")
}

func TestUnreachableSymbols_NoSymbolsIsNotAnError(t *testing.T) {
	t.Parallel()

	result, err := reachability.New().
		UnreachableSymbols(context.Background(), t.TempDir(), nil).Get()
	require.NoError(t, err)
	assert.Empty(t, result)
}
