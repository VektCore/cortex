// Package domain is the innermost layer of Cortex.
//
// # Rules
//
//   - It MUST NOT import from application, infrastructure, or interfaces.
//   - It MUST NOT perform I/O (no net/http, no os, no database/sql).
//   - It MUST NOT depend on third-party libraries except pure helpers
//     (samber/mo for Option/Result, samber/lo for slices/maps).
//   - Every public function should be pure: no side effects, no globals.
//   - Errors are values: domain functions return Result[T] or (T, error),
//     never panic.
//
// # Layout
//
// One subpackage per aggregate or shared concept:
//   - finding/  — the Finding aggregate (a single SAST hallazgo)
//   - scan/     — the Scan aggregate (one engine execution)
//   - gate/     — the GatePolicy aggregate (declarative quality gate)
//   - ruleset/  — Rulesets enabled per scanner/language
//   - shared/   — cross-cutting Value Objects (Language, Severity, errors)
//
// # Functional style
//
// Domain code is written in a functional style: immutable value objects,
// pure functions, composable pipelines via samber/lo. State changes return
// new aggregate instances rather than mutating receivers.
package domain
