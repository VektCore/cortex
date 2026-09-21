package projectprofile

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// tsconfig.json is the highest-value declaration a repository makes about
// itself, because "exclude" is unambiguous and enforced: TypeScript does not
// compile those paths, the bundler never reaches them, and nothing under them
// is deployed. It is also the one that was being ignored — the 1.1 GB vendored
// directory in the measurement was a single word in this array.

// maxExtendsDepth caps the `extends` chain. Real chains are one or two links;
// the cap only exists so a cycle cannot hang the scan.
const maxExtendsDepth = 8

// tsconfigFile is the subset of tsconfig.json this package reads. Everything
// else — compilerOptions, paths, plugins — is irrelevant to which files ship.
type tsconfigFile struct {
	Extends json.RawMessage `json:"extends"`
	Include []string        `json:"include"`
	Exclude []string        `json:"exclude"`
}

// resolvedTSConfig is a tsconfig after the `extends` chain has been walked.
// The file each array came from is kept, because "exclude" entries are
// relative to the directory of the file that declared them, not to the
// directory of the file that inherited them.
type resolvedTSConfig struct {
	excludeFile string
	exclude     []string
	includeFile string
	include     []string
}

// readTSConfig parses one tsconfig at rel. A missing file is silently nothing;
// a malformed one is a Note. Neither is an error: this package must never be
// the reason a scan fails.
func readTSConfig(root, rel string) (tsconfigFile, bool, []Note) {
	raw, err := os.ReadFile(abs(root, rel))
	if err != nil {
		return tsconfigFile{}, false, nil
	}

	var cfg tsconfigFile
	if err := json.Unmarshal(stripJSONC(raw), &cfg); err != nil {
		return tsconfigFile{}, false, []Note{{
			File:   rel,
			Reason: "unreadable as JSON or JSONC, so it contributes no exclusions: " + err.Error(),
		}}
	}
	return cfg, true, nil
}

// resolveTSConfig walks the `extends` chain and returns the effective include
// and exclude. TypeScript inherits an array from the base only when the child
// does not declare it, so the walk stops as soon as both are known.
func resolveTSConfig(root, rel string) (resolvedTSConfig, []string, []Note) {
	var (
		out   resolvedTSConfig
		read  []string
		notes []Note
	)

	for depth := 0; depth < maxExtendsDepth && rel != ""; depth++ {
		cfg, ok, ns := readTSConfig(root, rel)
		notes = append(notes, ns...)
		if !ok {
			break
		}
		read = append(read, rel)

		if out.exclude == nil && cfg.Exclude != nil {
			out.exclude, out.excludeFile = cfg.Exclude, rel
		}
		if out.include == nil && cfg.Include != nil {
			out.include, out.includeFile = cfg.Include, rel
		}
		if out.exclude != nil && out.include != nil {
			break
		}

		next, ns := resolveExtends(rel, cfg.Extends)
		notes = append(notes, ns...)
		rel = next
	}
	return out, read, notes
}

// resolveExtends returns the root-relative path of the base config, or "" when
// there is none to follow. Only relative paths are followed: `extends` may
// also name an npm package ("@tsconfig/next/tsconfig.json"), which lives in
// node_modules and is resolved by Node's algorithm — out of scope for a
// read-only, no-dependency reader, and recorded as a Note so the gap is
// visible rather than assumed empty.
func resolveExtends(rel string, raw json.RawMessage) (string, []Note) {
	if len(raw) == 0 {
		return "", nil
	}

	var target string
	if err := json.Unmarshal(raw, &target); err != nil {
		return "", []Note{{File: rel, Reason: `"extends" is an array or an object; only a single base config is followed`}}
	}
	if target == "" {
		return "", nil
	}
	if !strings.HasPrefix(target, "./") && !strings.HasPrefix(target, "../") {
		return "", []Note{{
			File:   rel,
			Reason: fmt.Sprintf("%q extends the package %q, which is not resolved here; any exclude it declares is not applied", rel, target),
		}}
	}
	if path.Ext(target) != ".json" {
		target += ".json"
	}

	base, ok := joinUnderRoot(dirOf(rel), target)
	if !ok {
		return "", []Note{{File: rel, Reason: fmt.Sprintf("%q extends %q, which resolves outside the scan root; not followed", rel, target)}}
	}
	return base, nil
}

// tsconfigExclusions turns the resolved arrays into decisions.
func tsconfigExclusions(root string, r resolvedTSConfig) ([]Exclusion, []SourceRoot, []Note) {
	excl, notes := tsExcludeEntries(root, r)
	roots, includeNotes := tsIncludeEntries(root, r)
	return excl, roots, append(notes, includeNotes...)
}

func tsExcludeEntries(root string, r resolvedTSConfig) ([]Exclusion, []Note) {
	out := make([]Exclusion, 0, len(r.exclude))
	var notes []Note
	base := dirOf(r.excludeFile)

	for i, entry := range r.exclude {
		field := fmt.Sprintf("exclude[%d]", i)
		if hasGlob(entry) {
			notes = append(notes, Note{
				File:   r.excludeFile,
				Reason: fmt.Sprintf("%s is the glob %q; globs are not translated, so those files are still scanned", field, entry),
			})
			continue
		}
		rel, ok := joinUnderRoot(base, entry)
		if !ok {
			notes = append(notes, Note{
				File:   r.excludeFile,
				Reason: fmt.Sprintf("%s is %q, which is absolute or outside the scan root; ignored", field, entry),
			})
			continue
		}
		if !exists(root, rel) {
			notes = append(notes, Note{
				File:   r.excludeFile,
				Reason: fmt.Sprintf("%s is %q, which does not exist in the checkout; nothing to exclude", field, entry),
			})
			continue
		}
		out = append(out, Exclusion{
			Pattern: pattern(root, rel),
			Source:  SourceTSConfig,
			File:    r.excludeFile,
			Field:   field,
			Reason:  "TypeScript is configured not to compile it, so nothing under it is bundled or deployed",
		})
	}
	return out, notes
}

// tsIncludeEntries records the declared source roots. It never produces an
// exclusion: see SourceRoot for why inverting "include" is not safe.
func tsIncludeEntries(root string, r resolvedTSConfig) ([]SourceRoot, []Note) {
	out := make([]SourceRoot, 0, len(r.include))
	var notes []Note

	for i, entry := range r.include {
		field := fmt.Sprintf("include[%d]", i)
		head := strings.SplitN(strings.TrimSpace(filepath.ToSlash(entry)), "/", 2)[0]
		if head == "" || hasGlob(head) {
			notes = append(notes, Note{
				File:   r.includeFile,
				Reason: fmt.Sprintf("%s is %q, which is repository-wide; it narrows nothing", field, entry),
			})
			continue
		}
		rel, ok := joinUnderRoot(dirOf(r.includeFile), head)
		if !ok || !isDir(root, rel) {
			continue
		}
		out = append(out, SourceRoot{Path: rel, Source: SourceTSConfig, File: r.includeFile, Field: field})
	}
	return out, notes
}
