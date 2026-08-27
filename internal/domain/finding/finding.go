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
	fp := in.Fingerprint
	if fp == "" {
		fp = NewFingerprint(in.RuleID, in.Location, in.Snippet)
	}
	content := in.Content
	if content == "" {
		content = NewContentFingerprint(in.RuleID, in.Location, in.Snippet)
	}
	symbolFP := in.Symbol
	if symbolFP == "" {
		symbolFP = NewSymbolFingerprint(in.RuleID, in.SymbolName, in.Snippet)
	}
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
		snippet:      in.Snippet,
	})
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
func (f Finding) Languages() []shared.Language    { return append([]shared.Language(nil), f.languages...) }

// HasCWE reports whether a given CWE is associated with the finding.
func (f Finding) HasCWE(c CWE) bool {
	v, ok := f.cwe.Get()
	return ok && v == c
}
