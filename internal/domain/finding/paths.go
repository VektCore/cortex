package finding

import (
	"path/filepath"
	"strings"
)

// Path handling for findings. Scanners report paths in whatever form suits
// them — relative to the process working directory, absolute, or as a file://
// URI — and the form changes with how Cortex was invoked (local, in Docker, or
// against a clone in a temp directory). Every path rule in the product
// (gate path prefixes, the allowlist, baseline comparison) depends on those
// paths being stable, so they are normalized once, right after parsing.

// NormalizePath turns any of the forms a scanner may emit into a clean,
// slash-separated path relative to one of roots. The first root that matches
// wins; a path under none of them is returned cleaned but otherwise untouched.
func NormalizePath(raw string, roots []string) string {
	p := strings.TrimPrefix(raw, "file://")
	p = filepath.ToSlash(filepath.Clean(p))

	for _, root := range roots {
		r := strings.TrimSuffix(filepath.ToSlash(filepath.Clean(root)), "/")
		if r == "" || r == "." {
			continue
		}
		if trimmed, ok := trimRoot(p, r); ok {
			return trimmed
		}
	}
	return strings.TrimPrefix(p, "./")
}

func trimRoot(p, root string) (string, bool) {
	if p == root {
		return filepath.Base(p), true
	}
	if strings.HasPrefix(p, root+"/") {
		return strings.TrimPrefix(p, root+"/"), true
	}
	return "", false
}

// Relativize returns a copy of findings whose locations are normalized against
// roots. Fingerprints are recomputed, so this must run before any baseline
// diff — a finding normalized on one side and not the other would look new.
func Relativize(findings []Finding, roots []string) []Finding {
	if len(findings) == 0 {
		return nil
	}

	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		normalized := NormalizePath(f.location.File(), roots)
		if normalized == f.location.File() {
			out = append(out, f)
			continue
		}

		loc, err := NewLocation(LocationInput{
			File:      normalized,
			StartLine: f.location.StartLine(),
			EndLine:   f.location.EndLine(),
			StartCol:  f.location.StartCol(),
			EndCol:    f.location.EndCol(),
		}).Get()
		if err != nil {
			// An unrepresentable normalization keeps the original path rather
			// than dropping the finding.
			out = append(out, f)
			continue
		}
		out = append(out, f.WithLocation(loc))
	}
	return out
}

// PathMatches reports whether a path pattern covers file. Three forms are
// accepted, because callers write patterns by hand and expect all three to
// work:
//
//	tests/              prefix, and any nested "tests/" directory segment
//	services/*/tests/*  glob over the whole path
//	/src/vendor         plain prefix
//
// This is the single matcher used by path exclusion and by the gate allowlist,
// so both behave identically.
func PathMatches(file, pattern string) bool {
	if pattern == "" {
		return false
	}
	if strings.HasPrefix(file, pattern) {
		return true
	}
	if matched, err := filepath.Match(pattern, file); err == nil && matched {
		return true
	}

	segment := strings.Trim(pattern, "/")
	if segment == "" {
		return false
	}
	return strings.Contains(file, "/"+segment+"/") ||
		strings.HasSuffix(file, "/"+segment) ||
		strings.HasPrefix(file, segment+"/")
}

// ExcludePaths drops every finding whose file matches one of the patterns.
// Applied after the scan, it is the backstop for scanners that cannot exclude
// paths themselves.
func ExcludePaths(findings []Finding, patterns []string) []Finding {
	if len(findings) == 0 || len(patterns) == 0 {
		return findings
	}

	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if matchesAny(f.location.File(), patterns) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func matchesAny(file string, patterns []string) bool {
	for _, pat := range patterns {
		if PathMatches(file, pat) {
			return true
		}
	}
	return false
}
