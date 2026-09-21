package projectprofile

// Declarations this package sees and deliberately does not read. Each one is
// recorded as a Note when the file is present, so the gap is visible in the
// log instead of looking like "this repository declares nothing".

// pythonManifests are the Python packaging files, and the reason each is left
// alone.
//
// pyproject.toml and setup.cfg would need a TOML/INI parser. The standard
// library has neither, the only TOML parser in the module graph is an indirect
// dependency of viper that this package is not allowed to promote, and a
// hand-rolled TOML reader for one field is exactly the kind of code that fails
// quietly on a file shape nobody tested.
//
// The value lost is small, and that is the deciding argument. What setuptools
// declares is `packages.find.exclude` and `tool.*.exclude` — which directories
// go into the wheel. A directory left out of the wheel is usually tests or
// tooling, which still runs in CI and still holds credentials; it is not the
// dead, never-executed code that tsconfig's "exclude" identifies. The one
// genuinely valuable Python signal, a virtualenv, is already in Cortex's
// default exclude list and is not declared in pyproject.toml anyway.
var pythonManifests = []struct {
	file   string
	reason string
}{
	{
		file:   "pyproject.toml",
		reason: "present but not parsed: no TOML parser is available without a new dependency, and packaging excludes describe the wheel, not code that never runs",
	},
	{
		file:   "setup.cfg",
		reason: "present but not parsed: same reason as pyproject.toml",
	},
}

// pythonNotes records the Python manifests found at the scan root.
func pythonNotes(root string) []Note {
	var out []Note
	for _, m := range pythonManifests {
		if exists(root, m.file) {
			out = append(out, Note{File: m.file, Reason: m.reason})
		}
	}
	return out
}
