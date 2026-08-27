// Package gate implements the Quality Gate — the heart of Cortex's
// "SonarQube-like" behaviour.
//
// A GatePolicy is a declarative set of rules ("fail if ≥1 critical",
// "fail if >5 high in changed files"). Evaluating a policy against a set
// of findings produces a Verdict (sum type: Pass | Fail with reasons).
//
// Aggregate root: GatePolicy
// Value Objects:  GateRule, Threshold, Verdict, GateViolation
// Domain Services: Evaluator (pure function: (Policy, []Finding) → Verdict)
//
// The gate decision is the only thing CI cares about: this package owns
// that decision and must remain fully deterministic and side-effect free.
package gate
