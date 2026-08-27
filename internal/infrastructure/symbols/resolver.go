// Package symbols names the function or class that contains a line of code.
//
// It backs the third fingerprint level, the one that lets a triage decision
// survive a function being moved. A real parser per language would be more
// precise, but the useful property here is cheap and language-agnostic: the
// nearest declaration above the line, which every mainstream language writes on
// its own line. Its failure mode is "no symbol", never "wrong symbol" — an
// unresolved symbol only costs matching precision.
package symbols

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/domain/shared"
)

// declPattern matches a declaration at the start of a line across the six MVP
// languages: python def/class, JS/TS function, arrow function and class, Go
// func (including methods), Java/C# methods and types.
var declPattern = regexp.MustCompile(
	`^\s*(?:` +
		`(?:async\s+)?def\s+(\w+)` +
		`|class\s+(\w+)` +
		`|func\s+(?:\([^)]*\)\s*)?(\w+)` +
		`|(?:export\s+)?(?:async\s+)?function\s*\*?\s*(\w+)` +
		`|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(` +
		`|(?:public|private|protected|internal|static|final|abstract|virtual|override)\s+[\w<>\[\],\s\.]*?(\w+)\s*\(` +
		`)`)

// Resolver reads source files to find enclosing symbols, caching each file it
// touches for the duration of a scan.
type Resolver struct {
	mu    sync.Mutex
	cache map[string][]string
}

// New returns a Resolver with an empty cache.
func New() *Resolver {
	return &Resolver{cache: make(map[string][]string)}
}

// Resolve returns the enclosing symbol for file:line, or None when it cannot
// tell: an unreadable file, a line above every declaration, or a language whose
// declarations this heuristic does not recognise.
func (r *Resolver) Resolve(
	_ context.Context, root, file string, line int,
) mo.Option[string] {
	lines, ok := r.lines(filepath.Join(root, file))
	if !ok || line < 1 {
		return mo.None[string]()
	}

	start := line - 1
	if start >= len(lines) {
		start = len(lines) - 1
	}
	for i := start; i >= 0; i-- {
		if name, found := declaredName(lines[i]); found {
			return shared.Some(name)
		}
	}
	return mo.None[string]()
}

func declaredName(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") {
		return "", false
	}

	match := declPattern.FindStringSubmatch(line)
	if match == nil {
		return "", false
	}
	for _, group := range match[1:] {
		if group != "" {
			return group, true
		}
	}
	return "", false
}

func (r *Resolver) lines(path string) ([]string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if cached, ok := r.cache[path]; ok {
		return cached, cached != nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		r.cache[path] = nil
		return nil, false
	}
	lines := strings.Split(string(raw), "\n")
	r.cache[path] = lines
	return lines, true
}
