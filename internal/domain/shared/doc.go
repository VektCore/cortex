// Package shared holds the shared kernel of Cortex's domain.
//
// Anything reused by multiple aggregates lives here:
//
//   - Language    — value object enumerating supported languages
//     (Python, JS/TS, Java, Go, CSharp, …).
//   - Severity    — ordered enum (Info < Low < Medium < High < Critical).
//   - DomainError — typed errors that travel up from aggregates.
//   - Clock       — interface used for deterministic timestamps in tests.
//
// Keep this package small: shared kernels become god-objects if anything
// remotely "useful" ends up here.
package shared
