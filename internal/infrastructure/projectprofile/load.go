package projectprofile

import (
	"context"
	"path"
)

// Load reads every declaration the repository makes about itself at root and
// returns the profile built from them.
//
// It has no error return by design. Every source is optional, a missing file
// is silence and a malformed one is a Note: a scanner that refused to run
// because a tsconfig.json had a stray comma would be a worse outcome than
// scanning a directory it did not have to. The zero-value Profile — nothing
// declared, nothing excluded — is always a correct answer.
//
// It is read-only and does not walk the tree. It opens a fixed set of files at
// the root, plus one tsconfig.json per declared workspace.
func Load(ctx context.Context, root string) Profile {
	p := Profile{Root: root}

	p.absorbTSConfig(root, "tsconfig.json")
	if ctx.Err() != nil {
		return p.finish()
	}

	p.absorbWorkspaces(ctx, root)
	if ctx.Err() != nil {
		return p.finish()
	}

	excl, notes := gitignoreExclusions(root)
	p.Exclusions = append(p.Exclusions, excl...)
	p.Notes = append(p.Notes, notes...)
	if len(excl) > 0 || len(notes) > 0 {
		p.FilesRead = append(p.FilesRead, ".gitignore")
	}

	if module, ok := readGoMod(root, "go.mod"); ok {
		p.GoModule = module
		p.FilesRead = append(p.FilesRead, "go.mod")
		p.Notes = append(p.Notes, Note{
			File:   "go.mod",
			Reason: "Go declares no excluded paths; vendor/ in particular is compiled into the binary and is not excluded here",
		})
	}

	p.Notes = append(p.Notes, pythonNotes(root)...)
	return p.finish()
}

// absorbTSConfig resolves one tsconfig, including its extends chain, and folds
// the result into the profile.
func (p *Profile) absorbTSConfig(root, rel string) {
	resolved, read, notes := resolveTSConfig(root, rel)
	p.FilesRead = append(p.FilesRead, read...)
	p.Notes = append(p.Notes, notes...)

	excl, roots, more := tsconfigExclusions(root, resolved)
	p.Exclusions = append(p.Exclusions, excl...)
	p.SourceRoots = append(p.SourceRoots, roots...)
	p.Notes = append(p.Notes, more...)
}

// absorbWorkspaces expands package.json "workspaces" and reads the
// tsconfig.json of each workspace. In a monorepo the root tsconfig often
// declares nothing and every real exclude lives one level down.
func (p *Profile) absorbWorkspaces(ctx context.Context, root string) {
	globs, notes, ok := readPackageJSON(root, "package.json")
	p.Notes = append(p.Notes, notes...)
	if !ok {
		return
	}
	p.FilesRead = append(p.FilesRead, "package.json")
	p.Workspaces = globs

	dirs, more := workspaceDirs(root, globs)
	p.Notes = append(p.Notes, more...)
	for _, dir := range dirs {
		if ctx.Err() != nil {
			return
		}
		p.absorbTSConfig(root, path.Join(dir, "tsconfig.json"))
	}
}

// finish makes the profile deterministic and drops duplicate patterns, keeping
// the first declaration of each — tsconfig before .gitignore, since it is read
// first and is the stronger statement.
func (p Profile) finish() Profile {
	p.Exclusions = dedupeExclusions(p.Exclusions)
	sortExclusions(p.Exclusions)
	p.FilesRead = dedupe(p.FilesRead)
	return p
}

func dedupeExclusions(in []Exclusion) []Exclusion {
	seen := make(map[string]struct{}, len(in))
	out := make([]Exclusion, 0, len(in))
	for _, e := range in {
		if e.Pattern == "" {
			continue
		}
		if _, ok := seen[e.Pattern]; ok {
			continue
		}
		seen[e.Pattern] = struct{}{}
		out = append(out, e)
	}
	return out
}
