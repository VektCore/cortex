package projectprofile

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Path helpers. Everything inside a Profile is a slash-separated path relative
// to the scan root, because that is the form finding.PathMatches and every
// scanner adapter expect. Absolute paths only exist long enough to stat a file.

// abs joins a root-relative slash path onto the scan root.
func abs(root, rel string) string {
	return filepath.Join(root, filepath.FromSlash(rel))
}

// dirOf returns the directory of a root-relative file, "" for the root itself.
func dirOf(rel string) string {
	d := path.Dir(rel)
	if d == "." || d == "/" {
		return ""
	}
	return d
}

// joinUnderRoot resolves entry against base and reports whether the result
// stays inside the scan root. A declaration that points outside the repository
// (`../shared`, an absolute path) is never turned into an exclusion: the
// pattern would be meaningless to the scanners and could match by accident.
func joinUnderRoot(base, entry string) (string, bool) {
	e := filepath.ToSlash(strings.TrimSpace(entry))
	if e == "" || path.IsAbs(e) || filepath.IsAbs(entry) {
		return "", false
	}
	joined := path.Clean(path.Join(base, e))
	if joined == "." || joined == ".." || strings.HasPrefix(joined, "../") {
		return "", false
	}
	return joined, true
}

// hasGlob reports whether a pattern contains glob syntax.
//
// Glob entries are never translated into exclusions. TypeScript, gitignore,
// Semgrep, ESLint and Cortex's own matcher all read `*` and `**` differently —
// filepath.Match, which Cortex uses, does not implement `**` at all — so a
// translated glob would exclude a different set of files in every tool. A
// pattern that means one thing to the scanner and another to the report is how
// a finding disappears without anyone noticing.
func hasGlob(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[")
}

// isDir reports whether rel exists under root and is a directory. This is not
// a heuristic about the path's name: it resolves what the declaration refers
// to, so the emitted pattern can carry the trailing slash that marks a
// directory.
func isDir(root, rel string) bool {
	info, err := os.Stat(abs(root, rel))
	return err == nil && info.IsDir()
}

// exists reports whether rel exists under root at all.
func exists(root, rel string) bool {
	_, err := os.Stat(abs(root, rel))
	return err == nil
}

// pattern renders a root-relative path as a Cortex exclude pattern, with the
// trailing slash that marks a directory when the target is one.
func pattern(root, rel string) string {
	if isDir(root, rel) {
		return rel + "/"
	}
	return rel
}
