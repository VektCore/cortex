package projectprofile

import (
	"fmt"
	"sort"
	"strings"
)

// Source names the declaration a decision came from. The values are the
// literal file names because they are shown to operators as evidence.
type Source string

// The declarations this package understands.
const (
	SourceTSConfig    Source = "tsconfig.json"
	SourceGitignore   Source = ".gitignore"
	SourcePackageJSON Source = "package.json"
	SourceGoMod       Source = "go.mod"
	SourcePyProject   Source = "pyproject.toml"
)

// Exclusion is one path pattern the repository declares out of scope, with the
// evidence for it. Every field is meant to be shown: an operator who sees
// fewer findings than expected must be able to ask "why was this skipped" and
// get an answer that names a file and a key inside it.
//
// Pattern is in Cortex's own exclude syntax (see finding.PathMatches), so it
// can be appended to the operator's exclude list unchanged.
type Exclusion struct {
	// Pattern is the exclude pattern, relative to the scan root, with a
	// trailing slash when the target was confirmed to be a directory.
	Pattern string
	// Source is the kind of declaration.
	Source Source
	// File is the declaring file, relative to the scan root.
	File string
	// Field is the key inside that file, e.g. `exclude[1]`.
	Field string
	// Reason is one sentence explaining the exclusion to a human.
	Reason string
}

// String renders the exclusion as one operator-readable line.
func (e Exclusion) String() string {
	return fmt.Sprintf("exclude %s — %s %s: %s", e.Pattern, e.File, e.Field, e.Reason)
}

// SourceRoot is a directory the repository declares as its compiled or
// published source.
//
// It is informational and nothing here ever derives an exclusion from it.
// Inverting an inclusion ("everything outside src/ is not compiled, so skip
// it") is precisely the judgement call this package refuses to make: code that
// TypeScript does not compile — build scripts, serverless handlers, CI
// tooling — still runs, and still has vulnerabilities.
type SourceRoot struct {
	// Path is the declared root, relative to the scan root.
	Path string
	// Source is the kind of declaration.
	Source Source
	// File is the declaring file, relative to the scan root.
	File string
	// Field is the key inside that file.
	Field string
}

// Note records something the profile saw and deliberately did not act on: a
// malformed file, a glob it will not translate, a declaration it does not
// trust. Notes exist so that "found nothing" and "found something and chose to
// ignore it" are distinguishable in the log.
type Note struct {
	// File is the file the note is about, relative to the scan root.
	File string
	// Reason explains what was skipped and why.
	Reason string
}

// String renders the note as one operator-readable line.
func (n Note) String() string { return fmt.Sprintf("note %s: %s", n.File, n.Reason) }

// Profile is everything a repository declares about itself that Cortex can
// cheaply use. The zero value is a repository that declared nothing, which is
// also what a completely unreadable repository produces.
type Profile struct {
	// Root is the scan root the profile was loaded from.
	Root string
	// Exclusions are the paths the repository declared out of scope.
	Exclusions []Exclusion
	// SourceRoots are the declared source directories. Informational.
	SourceRoots []SourceRoot
	// Workspaces are the workspace globs declared in package.json, as written.
	Workspaces []string
	// GoModule is the module path from go.mod, empty when there is none.
	GoModule string
	// Notes are the decisions not to act, with their reasons.
	Notes []Note
	// FilesRead lists the declaration files actually parsed, relative to Root.
	FilesRead []string
}

// ExcludeGlobs returns the exclusion patterns alone, sorted and deduplicated,
// for callers that only need the list. Prefer ComposeWith, which keeps the
// operator's own patterns first.
func (p Profile) ExcludeGlobs() []string {
	out := make([]string, 0, len(p.Exclusions))
	for _, e := range p.Exclusions {
		out = append(out, e.Pattern)
	}
	return dedupe(out)
}

// ComposeWith appends the declared exclusions to the operator's configured
// ones. The operator's patterns always come first and are never dropped,
// rewritten or reordered: this package adds to their policy, it does not
// override it.
func (p Profile) ComposeWith(operator []string) []string {
	out := make([]string, 0, len(operator)+len(p.Exclusions))
	out = append(out, operator...)
	for _, e := range p.Exclusions {
		out = append(out, e.Pattern)
	}
	return dedupe(out)
}

// Explain renders the full decision log: what was read, what was excluded on
// whose authority, and what was seen and ignored. The caller is expected to
// log this whenever the profile contributes any exclusion — an exclusion the
// operator cannot see is worse than no exclusion at all.
func (p Profile) Explain() string {
	var b strings.Builder
	fmt.Fprintf(&b, "project profile for %s\n", p.Root)

	if len(p.FilesRead) == 0 {
		b.WriteString("  read: nothing; the repository declares no manifest this package understands\n")
	} else {
		fmt.Fprintf(&b, "  read: %s\n", strings.Join(p.FilesRead, ", "))
	}

	if len(p.Exclusions) == 0 {
		b.WriteString("  no declared exclusions; the scan covers everything the operator configured\n")
	}
	for _, e := range p.Exclusions {
		fmt.Fprintf(&b, "  %s\n", e)
	}
	for _, r := range p.SourceRoots {
		fmt.Fprintf(&b, "  source root %s — %s %s (informational, nothing excluded from it)\n",
			r.Path, r.File, r.Field)
	}
	for _, n := range p.Notes {
		fmt.Fprintf(&b, "  %s\n", n)
	}
	return b.String()
}

// dedupe keeps the first occurrence of each pattern and preserves order, so
// the operator's patterns stay where they were and the first declaration of a
// path keeps the credit for it.
func dedupe(patterns []string) []string {
	seen := make(map[string]struct{}, len(patterns))
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// sortExclusions orders by pattern so two runs over the same repository
// produce byte-identical output; the report is compared across runs.
func sortExclusions(in []Exclusion) {
	sort.SliceStable(in, func(i, j int) bool { return in[i].Pattern < in[j].Pattern })
}
