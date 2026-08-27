// Package reachability decides, cheaply and conservatively, whether the code
// holding a finding is called from anywhere in the project.
//
// This is not interprocedural analysis. It answers one narrow question — is the
// enclosing symbol referenced anywhere outside its own declaration — and
// answers "unknown" whenever it cannot be sure. That is enough to separate a
// weakness on a live path from one in a helper nobody calls any more, which is
// the difference between a queue people work through and a queue people mute.
//
// Every guard here exists to avoid the expensive mistake: calling live code
// dead. Frameworks invoke handlers by name, exported symbols are called by
// other projects, and reflection is invisible to a text search. When any of
// those apply, the answer is "unknown".
package reachability

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// entrypointNames are symbols a framework or runtime calls, so an absent
// reference proves nothing.
var entrypointNames = map[string]struct{}{
	"main": {}, "init": {}, "setup": {}, "run": {}, "start": {},
	"handler": {}, "handle": {}, "index": {}, "app": {}, "application": {},
	"lambda_handler": {}, "__init__": {}, "__main__": {}, "constructor": {},
	"configure": {}, "register": {}, "middleware": {}, "serve": {},
}

// entrypointFiles are files whose contents are invoked from outside the
// project by definition.
var entrypointFilePrefixes = []string{
	"main.", "app.", "index.", "server.", "wsgi.", "asgi.", "manage.",
	"program.", "startup.", "__init__.", "__main__.",
}

// sourceExtensions are the files worth searching for references.
var sourceExtensions = map[string]struct{}{
	".py": {}, ".js": {}, ".jsx": {}, ".ts": {}, ".tsx": {}, ".mjs": {},
	".go": {}, ".java": {}, ".cs": {}, ".rb": {}, ".php": {}, ".kt": {},
}

// skipDirs are never searched: references from vendored code say nothing about
// the project's own call graph.
var skipDirs = map[string]struct{}{
	"node_modules": {}, "vendor": {}, ".git": {}, ".venv": {}, "venv": {},
	"dist": {}, "build": {}, "target": {}, "__pycache__": {},
	"site-packages": {}, ".tox": {}, "bin": {}, "obj": {},
}

// Analyzer counts references to symbols across a project, caching the file list
// and the contents it reads for the duration of a scan.
type Analyzer struct {
	mu    sync.Mutex
	files map[string][]string // root → source files
	body  map[string]string   // path → contents
}

// New returns an Analyzer with empty caches.
func New() *Analyzer {
	return &Analyzer{
		files: make(map[string][]string),
		body:  make(map[string]string),
	}
}

// UnreachableSymbols returns, for each symbol asked about, whether nothing in
// the project references it.
//
// A symbol absent from the result map is "unknown", not "reachable": callers
// must treat the two differently.
func (a *Analyzer) UnreachableSymbols(
	ctx context.Context, root string, refs []ports.SymbolRef,
) mo.Result[map[string]bool] {
	if len(refs) == 0 {
		return shared.Ok(map[string]bool{})
	}

	files, err := a.sourceFiles(root)
	if err != nil {
		return shared.Err[map[string]bool](err)
	}

	out := make(map[string]bool, len(refs))
	for _, ref := range refs {
		select {
		case <-ctx.Done():
			return shared.Err[map[string]bool](ctx.Err())
		default:
		}

		symbol := ref.Symbol
		if _, done := out[symbol]; done {
			continue
		}
		if !analyzable(symbol) || isEntrypointFile(ref.File) {
			continue // leave it unknown
		}

		references, decisive := a.countReferences(files, symbol)
		if !decisive {
			continue
		}
		out[symbol] = references == 0
	}
	return shared.Ok(out)
}

// analyzable rejects the symbols where an absent reference proves nothing:
// entrypoints, exported API, and names too short or too common to search for.
func analyzable(symbol string) bool {
	if len(symbol) < 4 {
		// "get", "run", "db" — a text search would match everywhere.
		return false
	}
	if _, isEntry := entrypointNames[strings.ToLower(symbol)]; isEntry {
		return false
	}
	// An initial capital means exported in Go and conventional for types
	// elsewhere: callers may live outside this repository.
	if r := rune(symbol[0]); unicode.IsUpper(r) {
		return false
	}
	return true
}

// countReferences counts uses of symbol outside its own declaration. The bool
// reports whether the count can be trusted: a file the analyzer could not read,
// or a declaration it never found, makes the answer unknown.
func (a *Analyzer) countReferences(files []string, symbol string) (int, bool) {
	pattern, err := regexp.Compile(`\b` + regexp.QuoteMeta(symbol) + `\b`)
	if err != nil {
		return 0, false
	}
	declaration := regexp.MustCompile(
		`^\s*(?:(?:async\s+)?def|class|func|function|const|let|var|public|private|protected|internal|static)\b[^\n]*\b` +
			regexp.QuoteMeta(symbol) + `\b`)

	references := 0
	sawDeclaration := false

	for _, path := range files {
		content, ok := a.contents(path)
		if !ok {
			return 0, false
		}
		if !strings.Contains(content, symbol) {
			continue
		}

		if isTestFile(path) {
			// A test calling the function does not make it reachable in
			// production, but it does mean somebody still uses it. Treat it as
			// inconclusive rather than dead.
			if pattern.MatchString(content) {
				return 0, false
			}
			continue
		}

		fileRefs, declared := scanFile(content, pattern, declaration)
		references += fileRefs
		sawDeclaration = sawDeclaration || declared
	}

	// Never having seen the declaration means the search missed the file the
	// symbol lives in; the count is meaningless.
	return references, sawDeclaration
}

// isEntrypointFile reports whether a file is invoked from outside the project.
func isEntrypointFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	for _, prefix := range entrypointFilePrefixes {
		if strings.HasPrefix(base, prefix) {
			return true
		}
	}
	return false
}

// scanFile counts references in one file, skipping the declaration itself and
// comments that merely mention the name.
func scanFile(content string, pattern, declaration *regexp.Regexp) (int, bool) {
	references := 0
	declared := false

	for _, line := range strings.Split(content, "\n") {
		if !pattern.MatchString(line) {
			continue
		}
		if declaration.MatchString(line) {
			declared = true
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "*") {
			continue
		}
		references++
	}
	return references, declared
}

// isTestFile reports whether a path belongs to a test, whose references say
// nothing about production reachability.
func isTestFile(path string) bool {
	return strings.HasPrefix(filepath.Base(path), "test") ||
		strings.Contains(path, "/tests/") ||
		strings.Contains(path, "/test/")
}

func (a *Analyzer) sourceFiles(root string) ([]string, error) {
	a.mu.Lock()
	if cached, ok := a.files[root]; ok {
		a.mu.Unlock()
		return cached, nil
	}
	a.mu.Unlock()

	var out []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if _, skip := skipDirs[entry.Name()]; skip {
				return fs.SkipDir
			}
			return nil
		}
		if _, ok := sourceExtensions[strings.ToLower(filepath.Ext(path))]; ok {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	a.files[root] = out
	a.mu.Unlock()
	return out, nil
}

func (a *Analyzer) contents(path string) (string, bool) {
	a.mu.Lock()
	if cached, ok := a.body[path]; ok {
		a.mu.Unlock()
		return cached, cached != ""
	}
	a.mu.Unlock()

	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}

	a.mu.Lock()
	a.body[path] = string(raw)
	a.mu.Unlock()
	return string(raw), true
}
