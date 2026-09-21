package finding_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// npmPkg is the shape every dependency-finding test uses: one npm package, so
// the tests read as "the same dependency seen twice" rather than as plumbing.
func npmPkg(name, version string) func(*finding.NewFindingInput) {
	return withPackage(finding.PackageInput{Ecosystem: "npm", Name: name, Version: version})
}

func mustPackage(t *testing.T, in finding.PackageInput) finding.Package {
	t.Helper()
	p, ok := finding.NewPackage(in).Get()
	require.True(t, ok)
	return p
}

func TestNewPackage_NoneWithoutName(t *testing.T) {
	t.Parallel()
	_, ok := finding.NewPackage(finding.PackageInput{Ecosystem: "npm"}).Get()
	assert.False(t, ok)
	_, blank := finding.NewPackage(finding.PackageInput{Name: "   "}).Get()
	assert.False(t, blank)
}

func TestNewPackage_CanonicalizesEcosystemSpelling(t *testing.T) {
	t.Parallel()
	for _, spelling := range []string{"Go", "gomod", "GoModules", "golang"} {
		p := mustPackage(t, finding.PackageInput{Ecosystem: spelling, Name: "golang.org/x/net"})
		assert.Equal(t, "go", p.Ecosystem(), spelling)
	}
	for _, spelling := range []string{"PyPI", "pip", "Poetry"} {
		p := mustPackage(t, finding.PackageInput{Ecosystem: spelling, Name: "requests"})
		assert.Equal(t, "pypi", p.Ecosystem(), spelling)
	}
	unknown := mustPackage(t, finding.PackageInput{Ecosystem: "Hex", Name: "plug"})
	assert.Equal(t, "hex", unknown.Ecosystem(), "unknown ecosystems pass through lower-cased")
}

func TestNewPackage_FoldsCaseOnlyWhereTheRegistryDoes(t *testing.T) {
	t.Parallel()
	pypi := mustPackage(t, finding.PackageInput{Ecosystem: "PyPI", Name: "Flask"})
	assert.Equal(t, "flask", pypi.Name())

	goMod := mustPackage(t, finding.PackageInput{Ecosystem: "Go", Name: "github.com/BurntSushi/toml"})
	assert.Equal(t, "github.com/BurntSushi/toml", goMod.Name(),
		"Go module paths are case-sensitive; folding them merges real dependencies")
}

func TestDependencyFingerprint_IgnoresTheFileItWasNoticedIn(t *testing.T) {
	t.Parallel()
	pkg := mustPackage(t, finding.PackageInput{Ecosystem: "npm", Name: "minimatch", Version: "3.1.2"})
	a := finding.NewDependencyFingerprint("CVE-2026-27904", pkg)
	b := finding.NewDependencyFingerprint("CVE-2026-27904", pkg)
	assert.Equal(t, a, b)
	assert.Len(t, string(a), finding.FingerprintLength)
}

func TestDependencyFingerprint_IgnoresVersion(t *testing.T) {
	t.Parallel()
	old := mustPackage(t, finding.PackageInput{Ecosystem: "npm", Name: "minimatch", Version: "3.1.2"})
	bumped := mustPackage(t, finding.PackageInput{Ecosystem: "npm", Name: "minimatch", Version: "3.1.3"})
	assert.Equal(t,
		finding.NewDependencyFingerprint("CVE-1", old),
		finding.NewDependencyFingerprint("CVE-1", bumped),
		"a bump that does not fix the advisory is the same finding, not a new one")
}

func TestDependencyFingerprint_SeparatesEcosystems(t *testing.T) {
	t.Parallel()
	npm := mustPackage(t, finding.PackageInput{Ecosystem: "npm", Name: "redis"})
	pypi := mustPackage(t, finding.PackageInput{Ecosystem: "PyPI", Name: "redis"})
	assert.NotEqual(t,
		finding.NewDependencyFingerprint("CVE-1", npm),
		finding.NewDependencyFingerprint("CVE-1", pypi),
		"npm redis and PyPI redis are unrelated projects")
}

func TestDependencyFingerprint_SeparatesAdvisoriesAndPackages(t *testing.T) {
	t.Parallel()
	a := mustPackage(t, finding.PackageInput{Ecosystem: "npm", Name: "minimatch"})
	b := mustPackage(t, finding.PackageInput{Ecosystem: "npm", Name: "semver"})
	assert.NotEqual(t,
		finding.NewDependencyFingerprint("CVE-1", a),
		finding.NewDependencyFingerprint("CVE-2", a))
	assert.NotEqual(t,
		finding.NewDependencyFingerprint("CVE-1", a),
		finding.NewDependencyFingerprint("CVE-1", b))
}

func TestDependencyFingerprint_EmptyWhenIncomplete(t *testing.T) {
	t.Parallel()
	pkg := mustPackage(t, finding.PackageInput{Ecosystem: "npm", Name: "minimatch"})
	assert.True(t, finding.NewDependencyFingerprint("", pkg).Empty())
	assert.True(t, finding.NewDependencyFingerprint("  ", pkg).Empty())
	assert.True(t, finding.NewDependencyFingerprint("CVE-1", finding.Package{}).Empty())
}

func TestFinding_DependencyIdentityIgnoresTheManifest(t *testing.T) {
	t.Parallel()
	bun := build(t,
		withRule("CVE-2026-27904"), withSource("osv"), withFile("bun.lock"),
		npmPkg("minimatch", "3.1.2"))
	lock := build(t,
		withRule("CVE-2026-27904"), withSource("osv"), withFile("package-lock.json"),
		npmPkg("minimatch", "3.1.2"))

	assert.True(t, bun.IsDependency())
	assert.Equal(t, bun.Fingerprint(), lock.Fingerprint())
	assert.Equal(t, bun.ContentFingerprint(), lock.ContentFingerprint())
	assert.Equal(t, bun.SymbolFingerprint(), lock.SymbolFingerprint())
	assert.Len(t, finding.Deduplicate([]finding.Finding{bun, lock}), 1)
}

func TestFinding_CodeFindingsKeepLocationIdentity(t *testing.T) {
	t.Parallel()
	a := build(t, withFile("src/a.go"))
	b := build(t, withFile("src/b.go"))
	assert.False(t, a.IsDependency())
	assert.NotEqual(t, a.Fingerprint(), b.Fingerprint())
	assert.Len(t, finding.Deduplicate([]finding.Finding{a, b}), 2)
}

func TestFinding_FallsBackWhenPackageIdentityIsUnusable(t *testing.T) {
	t.Parallel()
	// No rule id is impossible (New rejects it), so the realistic incomplete
	// case is a package that never made it past NewPackage: identity must be
	// the existing location-based one, never a worse one.
	const snippet = "\"minimatch\": \"3.1.2\""
	bun := build(t, withSource("osv"), withFile("bun.lock"),
		withSnippet(snippet), npmPkg("", "3.1.2"))
	lock := build(t, withSource("osv"), withFile("package-lock.json"),
		withSnippet(snippet), npmPkg("", ""))
	assert.False(t, bun.IsDependency())
	assert.NotEqual(t, bun.Fingerprint(), lock.Fingerprint())
	assert.Equal(t, finding.NewFingerprint(bun.RuleID(), bun.Location(), snippet),
		bun.Fingerprint(), "unchanged from the pre-existing scheme")
}

func TestFinding_StoredFingerprintStillWins(t *testing.T) {
	t.Parallel()
	f := build(t, withRule("CVE-1"), npmPkg("minimatch", "3.1.2"),
		func(in *finding.NewFindingInput) { in.Fingerprint = "deadbeefdeadbeef" })
	assert.Equal(t, finding.Fingerprint("deadbeefdeadbeef"), f.Fingerprint())
}

func TestRelativize_DoesNotReIdentifyDependencyFindings(t *testing.T) {
	t.Parallel()
	f := build(t, withRule("CVE-1"), withSource("osv"),
		withFile("/tmp/cortex-src-1/bun.lock"), npmPkg("minimatch", "3.1.2"))
	before := f.Fingerprint()

	out := finding.Relativize([]finding.Finding{f}, []string{"/tmp/cortex-src-1"})
	require.Len(t, out, 1)
	assert.Equal(t, "bun.lock", out[0].Location().File())
	assert.Equal(t, before, out[0].Fingerprint(),
		"normalizing the manifest path must not change what the finding is")
}

func TestWithSymbol_LeavesDependencyIdentityAlone(t *testing.T) {
	t.Parallel()
	f := build(t, withRule("CVE-1"), npmPkg("minimatch", "3.1.2"))
	assert.Equal(t, f.SymbolFingerprint(), f.WithSymbol("main").SymbolFingerprint())
}

func TestCrossScanner_GroupsDependenciesByAdvisoryNotByLine(t *testing.T) {
	t.Parallel()
	cwe := finding.CWE("CWE-1333")
	sameLine := func(rule finding.RuleID, name string, src finding.ScannerName) finding.Finding {
		return build(t, withRule(rule), withSource(src), withFile("bun.lock"),
			npmPkg(name, "1.0.0"),
			func(in *finding.NewFindingInput) { in.CWE = shared.Some(cwe) })
	}
	// Two unrelated advisories sharing one CWE at bun.lock:1 — the position a
	// lockfile finding always has.
	one := sameLine("CVE-1", "minimatch", "osv")
	two := sameLine("CVE-2", "semver", "osv")
	// The same advisory seen by a second tool: corroboration, not a duplicate.
	alsoOne := sameLine("CVE-1", "minimatch", "trivy")

	got := finding.DeduplicateCrossScanner([]finding.Finding{one, two, alsoOne})
	assert.Len(t, got.Findings, 2, "distinct advisories must not merge on file+line")
	assert.Equal(t, 1, got.Corroborated)
}
