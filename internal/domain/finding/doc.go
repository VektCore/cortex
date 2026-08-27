// Package finding models a single SAST finding as a domain aggregate.
//
// A Finding is the atomic unit of SAST output: a rule that fired at a
// specific location with a known severity and (optionally) a CWE/OWASP
// mapping.
//
// Aggregate root: Finding
// Value Objects:  Severity, CWE, OWASP, Location, RuleID, Fingerprint, Message
// Domain Events:  Detected, FindingDeduplicated, Suppressed
//
// Invariants enforced here:
//   - Severity is one of {Info, Low, Medium, High, Critical}.
//   - Fingerprint is a deterministic hash of (RuleID, file, startLine,
//     normalized snippet) — two findings with the same fingerprint are
//     duplicates by definition.
//   - A Finding cannot exist without a Location and a Severity.
package finding
