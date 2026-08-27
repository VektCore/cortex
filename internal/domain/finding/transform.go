package finding

import (
	"github.com/vektcore/cortex/internal/domain/shared"
)

// Immutable transformers. Each returns a new Finding; the receiver is never
// mutated, matching the aggregate rules in the architecture docs.

// WithCWE returns a copy carrying c. The fingerprint is unchanged because the
// CWE is not one of its inputs — enriching a finding never turns it into a
// different finding for deduplication or baseline purposes.
func (f Finding) WithCWE(c CWE) Finding {
	out := f
	out.cwe = shared.Some(c)
	return out
}

// WithSeverity returns a copy at severity s. Invalid values are ignored so a
// severity policy can never produce an unrepresentable finding.
func (f Finding) WithSeverity(s shared.Severity) Finding {
	if !s.IsValid() {
		return f
	}
	out := f
	out.severity = s
	return out
}

// WithLocation returns a copy at loc, recomputing the fingerprint: the file
// path and line numbers ARE fingerprint inputs, so a relocated finding must be
// re-identified. Callers that normalize paths must do it once, before any
// baseline comparison.
func (f Finding) WithLocation(loc Location) Finding {
	out := f
	out.location = loc
	out.fingerprint = NewFingerprint(f.ruleID, loc, f.snippet)
	out.content = NewContentFingerprint(f.ruleID, loc, f.snippet)
	return out
}

// WithReachability returns a copy carrying the analysis result.
func (f Finding) WithReachability(r Reachability) Finding {
	out := f
	out.reachability = r
	return out
}

// WithMessage returns a copy with a different message. Used by adapters that
// learn something after parsing — a secret confirmed to be still valid, say.
func (f Finding) WithMessage(m Message) Finding {
	out := f
	out.message = m
	return out
}

// WithSymbol returns a copy that knows which function or class contains it,
// recomputing the symbol fingerprint — the identity that survives a function
// being moved.
func (f Finding) WithSymbol(symbol string) Finding {
	out := f
	out.symbolName = symbol
	out.symbol = NewSymbolFingerprint(f.ruleID, symbol, f.snippet)
	return out
}
