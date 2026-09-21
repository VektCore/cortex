// Package projectprofile reads what a repository declares about itself and
// turns those declarations into path exclusions for the scan.
//
// The problem it solves is measured, not theoretical: on one real repository
// Cortex scanned a 1.1 GB vendored directory that the project's own
// tsconfig.json lists under "exclude". It is not compiled, not bundled and not
// deployed, and it produced a third of the findings in the report. The
// information was in the repository the whole time; nothing read it.
//
// # The rule this package is built around
//
// A false negative in a security scanner is silent. Scanning a few extra files
// costs CPU; skipping a file that ships costs a vulnerability nobody ever
// hears about. So every decision here is biased the same way:
//
//   - Exclude only on an explicit declaration by the repository. Never on a
//     heuristic. A directory called "vendor" is not evidence of anything; a
//     "vendor" entry in tsconfig's "exclude" is.
//   - When a declaration is ambiguous — a glob whose semantics differ between
//     TypeScript, Semgrep and Cortex's own matcher, a .gitignore line that may
//     name a file or a directory — do not exclude. Record a Note instead.
//   - Report every decision with its evidence. A silent exclusion is
//     indistinguishable from a missed scan, so each Exclusion carries the file,
//     the field and a sentence an operator can read.
//
// # What it reads
//
//	tsconfig.json    "exclude" (literal paths only), "extends" (local chains),
//	                 "include" recorded as declared source roots, never as an
//	                 exclusion.
//	package.json     "workspaces", used to find the tsconfig.json of each
//	                 workspace. "files" is deliberately not used.
//	.gitignore       root file, directory declarations only.
//	go.mod           module path. Go declares no excluded paths.
//
// pyproject.toml and setup.cfg are deliberately not parsed; see notes.go for
// the reason. Nothing here walks the tree: it opens a fixed set of files and
// resolves the workspace globs, and it is read-only.
//
// # Composing with the operator's configuration
//
// The output adds to config's exclude list, it never replaces it:
//
//	profile := projectprofile.Load(ctx, target)
//	exclude := profile.ComposeWith(cfg.ExcludePatterns())
//
// Load has no error return. An unreadable or malformed declaration means "no
// information", never a failed scan.
//
// # One property of the matcher to know about
//
// Cortex matches a pattern of a single path segment at any depth: "template/"
// covers src/ui/template/ as well as the root template/. The patterns produced
// here are therefore slightly wider than the declaration that justified them,
// which is why every one of them is required to name a path that exists in the
// checkout — a pattern for a directory that is not there can only ever match
// something the declaration did not mean.
package projectprofile
