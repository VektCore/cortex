package finding

import (
	"strings"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/domain/shared"
)

// Package identifies the dependency an advisory is about: the ecosystem it is
// published in, its name, and the resolved version that was found installed.
//
// It is what makes a software-composition finding identifiable independently of
// the manifest it was noticed in. A repository that commits both `bun.lock` and
// `package-lock.json` has osv-scanner report every advisory twice — once per
// file — and they are the same vulnerable package, so they must be one finding.
//
// The ecosystem is part of the identity because package names are only unique
// within a registry: npm's `redis` and PyPI's `redis` are unrelated projects.
type Package struct {
	ecosystem string
	name      string
	version   string
}

// PackageInput is the constructor argument struct, matching LocationInput and
// NewFindingInput. Every field arrives as the scanner spelled it; normalization
// happens here so that no adapter has to know the rules.
type PackageInput struct {
	// Ecosystem is the registry: "npm", "PyPI", "Go", "Maven"… Scanners
	// disagree on spelling, so it is canonicalized.
	Ecosystem string
	// Name is the package name as the registry knows it.
	Name string
	// Version is the resolved version that was found installed. Carried for
	// reporting; deliberately NOT part of the dependency fingerprint — see
	// NewDependencyFingerprint.
	Version string
}

// NewPackage normalizes input and returns the Package, or None when the name is
// empty. Absence is the common case — a Semgrep finding is about code, not a
// dependency — so this returns an Option rather than a Result: a finding with
// no package identity is not an error, it is a code finding.
func NewPackage(in PackageInput) mo.Option[Package] {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return shared.None[Package]()
	}
	ecosystem := canonicalEcosystem(in.Ecosystem)
	return shared.Some(Package{
		ecosystem: ecosystem,
		name:      canonicalPackageName(ecosystem, name),
		version:   strings.TrimSpace(in.Version),
	})
}

func (p Package) Ecosystem() string { return p.ecosystem }
func (p Package) Name() string      { return p.name }
func (p Package) Version() string   { return p.version }

// Equal reports value equality, including the version. Callers comparing
// identity rather than state want the dependency fingerprint instead.
func (p Package) Equal(o Package) bool {
	return p.ecosystem == o.ecosystem && p.name == o.name && p.version == o.version
}

// ecosystemAliases maps the spellings Cortex's SCA scanners actually emit onto
// one canonical token. It is a spelling table, not an ontology: osv-scanner
// says "Go" and "crates.io" where Trivy says "gomod" and "cargo", and two
// spellings of one registry would give the same package two identities — which
// is the bug this whole value object exists to prevent.
//
// Anything not listed passes through lower-cased, so an ecosystem neither tool
// has taught us about still produces a stable key.
var ecosystemAliases = map[string]string{
	"go": "go", "gomod": "go", "gomodules": "go", "golang": "go",
	"pypi": "pypi", "pip": "pypi", "python": "pypi", "poetry": "pypi",
	"npm": "npm", "node": "npm", "yarn": "npm", "pnpm": "npm", "bun": "npm",
	"maven": "maven", "gradle": "maven", "jar": "maven", "pom": "maven",
	"nuget": "nuget", "dotnet": "nuget",
	"crates.io": "cargo", "cargo": "cargo", "rust": "cargo",
	"rubygems": "rubygems", "gem": "rubygems", "bundler": "rubygems",
	"packagist": "packagist", "composer": "packagist",
}

func canonicalEcosystem(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if canonical, ok := ecosystemAliases[lower]; ok {
		return canonical
	}
	return lower
}

// caseInsensitiveEcosystems are the registries that treat package names
// case-insensitively, so `Flask` and `flask` are one PyPI project and must hash
// alike. Case is preserved everywhere else: a Go module path and a Maven
// coordinate are case-sensitive, and folding them would merge two real
// dependencies into one finding — a worse failure than reporting one twice.
var caseInsensitiveEcosystems = map[string]struct{}{
	"npm": {}, "pypi": {}, "nuget": {}, "packagist": {},
}

func canonicalPackageName(ecosystem, name string) string {
	if _, fold := caseInsensitiveEcosystems[ecosystem]; fold {
		return strings.ToLower(name)
	}
	return name
}
