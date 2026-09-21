package projectprofile

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// package.json contributes no exclusions of its own. It earns its place for
// one reason: "workspaces" says where the other packages of a monorepo live,
// and each of those packages has its own tsconfig.json whose "exclude" would
// otherwise never be read. A root-only reader finds nothing in a monorepo.
//
// "files" is deliberately not used. It is npm's allowlist for the published
// tarball, not a statement about which code runs: tests, build scripts and CI
// tooling are routinely left out of "files" and are routinely where a
// hardcoded credential or a command injection lives. Excluding on it would
// trade a large, silent false negative for a small speedup.
//
// Note that language_detection already knows the name "package.json", but only
// as a manifest-to-language mapping — it never opens the file. There is no
// parser there to reuse and nothing here duplicates it.

// maxWorkspaceDirs caps workspace expansion so a pathological glob cannot turn
// a cheap read into a tree walk.
const maxWorkspaceDirs = 256

// packageFile is the subset of package.json this package reads.
type packageFile struct {
	Files      []string        `json:"files"`
	Workspaces json.RawMessage `json:"workspaces"`
}

// readPackageJSON returns the workspace globs declared at rel.
func readPackageJSON(root, rel string) ([]string, []Note, bool) {
	raw, err := os.ReadFile(abs(root, rel))
	if err != nil {
		return nil, nil, false
	}

	var pkg packageFile
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return nil, []Note{{File: rel, Reason: "unreadable as JSON, so its workspaces are not expanded: " + err.Error()}}, false
	}

	var notes []Note
	if len(pkg.Files) > 0 {
		notes = append(notes, Note{
			File:   rel,
			Reason: `"files" is present but not used: it is the npm publish allowlist, and code left out of it (tests, scripts) still runs`,
		})
	}
	return parseWorkspaces(pkg.Workspaces), notes, true
}

// parseWorkspaces accepts both shapes npm and yarn allow: a bare array, or an
// object with a "packages" array.
func parseWorkspaces(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}

	var asArray []string
	if err := json.Unmarshal(raw, &asArray); err == nil {
		return asArray
	}

	var asObject struct {
		Packages []string `json:"packages"`
	}
	if err := json.Unmarshal(raw, &asObject); err == nil {
		return asObject.Packages
	}
	return nil
}

// workspaceDirs resolves the declared globs to directories that exist. Only
// directories inside the scan root are returned; a workspace pointing outside
// it is not ours to reason about.
func workspaceDirs(root string, globs []string) ([]string, []Note) {
	var (
		out   []string
		notes []Note
	)

	for _, g := range globs {
		rel, ok := joinUnderRoot("", g)
		if !ok {
			notes = append(notes, Note{File: "package.json", Reason: fmt.Sprintf("workspace %q resolves outside the scan root; skipped", g)})
			continue
		}
		matches, err := filepath.Glob(abs(root, rel))
		if err != nil {
			notes = append(notes, Note{File: "package.json", Reason: fmt.Sprintf("workspace glob %q is malformed; skipped", g)})
			continue
		}
		out = append(out, relativeDirs(root, matches)...)
		if len(out) >= maxWorkspaceDirs {
			notes = append(notes, Note{File: "package.json", Reason: fmt.Sprintf("more than %d workspace directories; the rest were not read", maxWorkspaceDirs)})
			break
		}
	}

	sort.Strings(out)
	return dedupe(out), notes
}

// relativeDirs keeps the directories among matches, as root-relative paths.
func relativeDirs(root string, matches []string) []string {
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		rel, err := filepath.Rel(root, m)
		if err != nil {
			continue
		}
		slash := filepath.ToSlash(rel)
		if strings.HasPrefix(slash, "../") || !isDir(root, slash) {
			continue
		}
		out = append(out, path.Clean(slash))
	}
	return out
}
