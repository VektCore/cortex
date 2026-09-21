package sarif

import (
	"path/filepath"
	"regexp"
	"strings"

	gosarif "github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/domain/finding"
)

// Properties a dependency finding carries once Cortex has written it, so the
// package survives a round trip through a document of our own.
const (
	PackageEcosystemProperty = "cortex/pkg.ecosystem"
	PackageNameProperty      = "cortex/pkg.name"
	PackageVersionProperty   = "cortex/pkg.version"
)

// osvPackage matches the one place osv-scanner states which package an advisory
// is about: its message prose. There is no structured field for it, and no PURL
// anywhere in its SARIF output.
//
//	Package 'minimatch@3.1.2' is vulnerable to 'CVE-2026-27904' (also known as …)
var osvPackage = regexp.MustCompile(`Package '([^']+)@([^@']+)' is vulnerable to`)

// Trivy, unlike osv, states it outright.
const (
	trivyPkgName    = "PkgName"
	trivyPkgVersion = "InstalledVersion"
)

// manifestEcosystems maps a dependency manifest onto the registry it describes.
//
// This lookup is why the table lives in infrastructure rather than in the
// domain: osv reports which advisory affects which package and never says which
// registry the package came from, so the only evidence available is the file it
// was noticed in. npm `redis` and PyPI `redis` are different packages, and
// without this they would share an identity.
var manifestEcosystems = map[string]string{
	"package-lock.json":  "npm",
	"bun.lock":           "npm",
	"bun.lockb":          "npm",
	"yarn.lock":          "npm",
	"pnpm-lock.yaml":     "npm",
	"package.json":       "npm",
	"requirements.txt":   "PyPI",
	"poetry.lock":        "PyPI",
	"Pipfile.lock":       "PyPI",
	"pyproject.toml":     "PyPI",
	"go.mod":             "Go",
	"go.sum":             "Go",
	"pom.xml":            "Maven",
	"build.gradle":       "Maven",
	"Cargo.lock":         "crates.io",
	"Gemfile.lock":       "RubyGems",
	"composer.lock":      "Packagist",
	"packages.lock.json": "NuGet",
}

// extractPackage recovers the package a dependency advisory is about.
//
// Absence is the normal case: a Semgrep or gitleaks result has no package, and
// returning None leaves the finding's identity exactly as it was. Nothing here
// can make an identity worse — it can only add the dependency key when there is
// enough evidence for one.
func extractPackage(
	result *gosarif.Result, scanner finding.ScannerName,
) mo.Option[finding.Package] {
	name, version := packageFromProperties(result)
	if name == "" {
		name, version = packageFromMessage(result)
	}
	if name == "" {
		return mo.None[finding.Package]()
	}

	return finding.NewPackage(finding.PackageInput{
		Ecosystem: ecosystemFor(result, scanner),
		Name:      name,
		Version:   version,
	})
}

// packageFromProperties reads Trivy's structured fields, and the properties
// Cortex itself writes, so a finding reloaded from a document Cortex produced
// is still recognised as a dependency.
func packageFromProperties(result *gosarif.Result) (name, version string) {
	if n := stringPropertyOr(result.Properties, PackageNameProperty); n != "" {
		return n, stringPropertyOr(result.Properties, PackageVersionProperty)
	}
	return stringPropertyOr(result.Properties, trivyPkgName),
		stringPropertyOr(result.Properties, trivyPkgVersion)
}

func packageFromMessage(result *gosarif.Result) (name, version string) {
	m := osvPackage.FindStringSubmatch(derefStr(result.Message.Text))
	if len(m) != 3 {
		return "", ""
	}
	return m[1], m[2]
}

// ecosystemFor decides the registry. A property Cortex wrote wins, then the
// manifest the advisory was reported against. An unknown manifest yields the
// empty string: NewPackage keeps the key stable without it, and guessing a
// registry would merge packages that merely share a name.
func ecosystemFor(result *gosarif.Result, scanner finding.ScannerName) string {
	if eco := stringPropertyOr(result.Properties, PackageEcosystemProperty); eco != "" {
		return eco
	}
	if eco := manifestEcosystems[filepath.Base(resultURI(result))]; eco != "" {
		return eco
	}
	// Go modules are the one case a path alone settles: osv reports them
	// against go.mod, but a vendored tree or a workspace can name the file
	// differently, and the package name is a module path.
	if scanner == "osv-scanner" && strings.Contains(resultURI(result), "go.") {
		return "Go"
	}
	return ""
}

// resultURI is the file a result points at, or "" when it points nowhere.
func resultURI(result *gosarif.Result) string {
	if len(result.Locations) == 0 || result.Locations[0].PhysicalLocation == nil {
		return ""
	}
	loc := result.Locations[0].PhysicalLocation
	if loc.ArtifactLocation == nil {
		return ""
	}
	return derefStr(loc.ArtifactLocation.URI)
}
