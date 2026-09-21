package projectprofile

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
)

// .gitignore is a weaker declaration than tsconfig's "exclude" and is treated
// as such.
//
// What it does say, unambiguously, is "this directory is not part of the
// committed source tree" — build output, caches, installed dependencies. What
// it does not say is "this code does not ship": git only enforces an ignore
// rule for untracked files, so a directory can be listed here and still be
// committed and deployed. That is a real shape — a directory added to
// .gitignore after it was already tracked — and excluding it would hide
// committed code.
//
// Four restrictions follow, and each one costs coverage on purpose:
//
//   - Only the .gitignore at the scan root. Nested ones apply to their own
//     directory and finding them means walking the tree, which this package
//     does not do.
//   - Only entries that resolve to a directory that exists in the checkout. A
//     bare `logs` might be a file, and a pattern for a path that is not there
//     excludes nothing while still being able to match something else: Cortex
//     matches a single path segment at any depth, so an unnecessary `out/`
//     would also hide `src/components/out/`.
//   - No globs. `*.log` and `**/public/sw.js` are left to be scanned.
//   - Nothing a `!` line re-includes, even partially.
//
// The exclusions it does produce carry Source SourceGitignore, so an operator
// who does not want this source can drop them by that field alone.

// ignoreLine is one usable .gitignore entry after normalization.
type ignoreLine struct {
	num   int
	raw   string
	clean string
}

// gitignoreExclusions reads the root .gitignore. A missing file is nothing.
func gitignoreExclusions(root string) ([]Exclusion, []Note) {
	const file = ".gitignore"

	data, err := os.ReadFile(abs(root, file))
	if err != nil {
		return nil, nil
	}

	candidates, negations, skippedGlobs := parseGitignore(data)
	out, notes := gitignoreDecisions(root, file, candidates, negations)

	if skippedGlobs > 0 {
		notes = append(notes, Note{
			File:   file,
			Reason: fmt.Sprintf("%d glob patterns were not translated; the files they cover are still scanned", skippedGlobs),
		})
	}
	return out, notes
}

// parseGitignore splits the file into directory candidates, negation patterns
// and a count of the globs it refused to translate.
func parseGitignore(data []byte) (candidates []ignoreLine, negations []string, globs int) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for num := 1; scanner.Scan(); num++ {
		line := strings.TrimRight(strings.TrimSpace(scanner.Text()), "/ \t")
		raw := strings.TrimSpace(scanner.Text())

		switch {
		case raw == "" || strings.HasPrefix(raw, "#"):
			continue
		case strings.HasPrefix(raw, "!"):
			negations = append(negations, strings.Trim(strings.TrimPrefix(raw, "!"), "/"))
			continue
		case hasGlob(raw) || strings.Contains(raw, `\`):
			globs++
			continue
		}

		if clean := strings.Trim(line, "/"); clean != "" {
			candidates = append(candidates, ignoreLine{num: num, raw: raw, clean: clean})
		}
	}
	return candidates, negations, globs
}

// gitignoreDecisions keeps only the candidates that resolve to a directory
// present in the checkout and that no negation reaches into.
func gitignoreDecisions(root, file string, candidates []ignoreLine, negations []string) ([]Exclusion, []Note) {
	out := make([]Exclusion, 0, len(candidates))
	var notes []Note

	for _, c := range candidates {
		field := fmt.Sprintf("line %d", c.num)
		if !isDir(root, c.clean) {
			continue // may name a file, or nothing at all: not evidence enough
		}
		if reincluded(c.clean, negations) {
			notes = append(notes, Note{
				File:   file,
				Reason: fmt.Sprintf("%s ignores %q but a %q rule re-includes part of it; not excluded", field, c.raw, "!"),
			})
			continue
		}
		out = append(out, Exclusion{
			Pattern: c.clean + "/",
			Source:  SourceGitignore,
			File:    file,
			Field:   field,
			Reason:  "declared ignored, so it is build output or an installed dependency rather than committed source",
		})
	}
	return out, notes
}

// reincluded reports whether any negation names the candidate or something
// inside it. A re-included path is a statement that the ignore is not total,
// which is exactly the ambiguity this package refuses to resolve.
func reincluded(clean string, negations []string) bool {
	for _, n := range negations {
		if n == clean || strings.HasPrefix(n, clean+"/") {
			return true
		}
	}
	return false
}
