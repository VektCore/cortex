package finding

import (
	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/domain/shared"
)

// Finding is the aggregate root for one SAST finding. It is an immutable
// value: all fields are unexported, set once at construction, and exposed
// through pure accessor methods.
type Finding struct {
	fingerprint Fingerprint
	// content and symbol are the coarser identities used to follow a finding
	// across refactors. See fingerprint.go.
	content Fingerprint
	symbol  Fingerprint
	// symbolName is the enclosing function/class, when a resolver found it.
	symbolName string
	// reachability is set by the optional reachability analysis.
	reachability Reachability
	ruleID       RuleID
	severity     shared.Severity
	cwe          mo.Option[CWE]
	owasp        mo.Option[OWASP]
	location     Location
	message      Message
	source       ScannerName
	languages    []shared.Language
	// pkg is the vulnerable dependency, present only on software-composition
	// findings. Its presence is what makes a finding "a dependency finding".
	pkg mo.Option[Package]
	// snippet is kept only to recompute the fingerprint when the location
	// changes (path normalization). It is never exposed.
	snippet string
}

// NewFindingInput is the parameter struct for New. Using a struct keeps
// the call site readable and lets us add optional fields without
// breaking existing callers.
type NewFindingInput struct {
	RuleID    RuleID
	Severity  shared.Severity
	Location  Location
	Message   Message
	Source    ScannerName
	Snippet   string // used for fingerprint normalization only
	CWE       mo.Option[CWE]
	OWASP     mo.Option[OWASP]
	Languages []shared.Language
	// Package, when present, marks this as a dependency finding and switches
	// its identity to the advisory + package key. Build it with NewPackage;
	// leaving it None keeps the location-based identities unchanged.
	Package mo.Option[Package]
	// Fingerprint, when set, is used as-is instead of being recomputed. Only
	// for reconstructing a finding that Cortex itself serialized: the snippet
	// is not part of that document, so recomputing would produce a different
	// identity for the same finding.
	Fingerprint Fingerprint
	// Content and Symbol are the coarser identities. Like Fingerprint, they are
	// recomputed when empty.
	Content Fingerprint
	Symbol  Fingerprint
	// SymbolName is the enclosing function or class, when known.
	SymbolName string
	// Reachability defaults to unknown.
	Reachability Reachability
}

// New validates input and constructs a Finding. Returns Err when any
// invariant is violated.
func New(in NewFindingInput) mo.Result[Finding] {
	if in.RuleID.Empty() {
		return shared.Err[Finding](shared.NewDomainError(
			"FINDING_NO_RULE", "ruleID is required"))
	}
	if !in.Severity.IsValid() {
		return shared.Err[Finding](shared.NewDomainError(
			"FINDING_BAD_SEVERITY", "severity is not a valid enum value"))
	}
	if in.Location.File() == "" {
		return shared.Err[Finding](shared.NewDomainError(
			"FINDING_NO_LOCATION", "location is required"))
	}
	if in.Source == "" {
		return shared.Err[Finding](shared.NewDomainError(
			"FINDING_NO_SOURCE", "source (scanner) is required"))
	}
	fp, content, symbolFP := identities(in)
	return shared.Ok(Finding{
		fingerprint:  fp,
		content:      content,
		symbol:       symbolFP,
		symbolName:   in.SymbolName,
		reachability: in.Reachability,
		ruleID:       in.RuleID,
		severity:     in.Severity,
		cwe:          in.CWE,
		owasp:        in.OWASP,
		location:     in.Location,
		message:      in.Message,
		source:       in.Source,
		languages:    append([]shared.Language(nil), in.Languages...),
		pkg:          in.Package,
		snippet:      in.Snippet,
	})
}

// identities computes the three fingerprints, honouring any the caller already
// supplied (a finding reconstructed from a document Cortex wrote carries them
// and must not be re-identified).
//
// A dependency finding is keyed on the advisory and the package at all three
// levels. The cascade exists to follow code through edits — lines moving, a
// function changing file — and none of that applies to a lockfile entry, so
// collapsing the levels costs nothing and keeps whichever level a consumer
// reads pointing at the same vulnerable dependency.
//
// The fallback is always the existing behaviour: no package identity, or one
// too incomplete to hash, and the location-based fingerprints are used
// unchanged. This can only ever merge duplicates, never split them.
func identities(in NewFindingInput) (exact, content, symbol Fingerprint) {
	if dep := dependencyKey(in.RuleID, in.Package); !dep.Empty() {
		return orElse(in.Fingerprint, dep), orElse(in.Content, dep), orElse(in.Symbol, dep)
	}
	return orElse(in.Fingerprint, NewFingerprint(in.RuleID, in.Location, in.Snippet)),
		orElse(in.Content, NewContentFingerprint(in.RuleID, in.Location, in.Snippet)),
		orElse(in.Symbol, NewSymbolFingerprint(in.RuleID, in.SymbolName, in.Snippet))
}

// dependencyKey is the dependency fingerprint for a finding that carries a
// package, and "" for every other finding.
func dependencyKey(rule RuleID, pkg mo.Option[Package]) Fingerprint {
	p, ok := pkg.Get()
	if !ok {
		return ""
	}
	return NewDependencyFingerprint(rule, p)
}

func orElse(supplied, computed Fingerprint) Fingerprint {
	if supplied != "" {
		return supplied
	}
	return computed
}

// Accessors. All return value types — no internal slice is ever exposed
// directly, preserving immutability.

func (f Finding) Fingerprint() Fingerprint        { return f.fingerprint }
func (f Finding) ContentFingerprint() Fingerprint { return f.content }
func (f Finding) SymbolFingerprint() Fingerprint  { return f.symbol }
func (f Finding) SymbolName() string              { return f.symbolName }
func (f Finding) Reachability() Reachability      { return f.reachability }
func (f Finding) RuleID() RuleID                  { return f.ruleID }
func (f Finding) Severity() shared.Severity       { return f.severity }
func (f Finding) CWE() mo.Option[CWE]             { return f.cwe }
func (f Finding) OWASP() mo.Option[OWASP]         { return f.owasp }
func (f Finding) Location() Location              { return f.location }
func (f Finding) Message() Message                { return f.message }
func (f Finding) Source() ScannerName             { return f.source }
func (f Finding) Package() mo.Option[Package]     { return f.pkg }
func (f Finding) Languages() []shared.Language    { return append([]shared.Language(nil), f.languages...) }

// IsDependency reports whether this is a software-composition finding — one
// about a package rather than about code — which is what decides that its
// identity is the advisory and the package instead of a file and a line.
func (f Finding) IsDependency() bool {
	return !f.dependencyFingerprint().Empty()
}

// dependencyFingerprint recomputes the dependency identity from the finding's
// own fields, or returns "" for a code finding.
func (f Finding) dependencyFingerprint() Fingerprint {
	return dependencyKey(f.ruleID, f.pkg)
}

// HasCWE reports whether a given CWE is associated with the finding.
func (f Finding) HasCWE(c CWE) bool {
	v, ok := f.cwe.Get()
	return ok && v == c
}
