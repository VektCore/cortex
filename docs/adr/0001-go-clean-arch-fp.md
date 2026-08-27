# ADR 0001 — Go + Clean Architecture + Functional Discipline

* **Date:** 2026-05-15
* **Status:** Accepted
* **Deciders:** Cortex core team

## Context

Cortex must run as a single step inside any CI/CD pipeline, scan code in
many languages, aggregate results, apply a Quality Gate, and publish to
several destinations. The product is conceptually similar to SonarQube,
Snyk, or Semgrep Cloud — but as a self-contained engine, not a SaaS.

We needed to pick:

1. The implementation language for the engine itself.
2. The architectural style.
3. The programming style (OOP-heavy vs functional-leaning).

## Decision

### Language: **Go 1.22+**

Reasons specific to this product:

- **Single static binary** — drop into any CI image without runtime
  prerequisites.
- **Fast startup** — matters for PR-level scans.
- **Native concurrency** — orchestrating N scanners in parallel is
  idiomatic with goroutines + `context.Context`.
- **Industry alignment in DevSecOps** — Trivy, gosec, gitleaks, syft,
  grype, OPA are all Go; integration and operator familiarity are
  high.
- **Cross-compilation** matrix is trivial via `GOOS`/`GOARCH`.

Languages considered and rejected:

- **Rust** — better FP ergonomics, but slower iteration speed and
  smaller talent pool for the kind of pipeline tooling we ship.
- **TypeScript + Effect** — best FP expressivity, but distributing a
  Node runtime into every CI image is friction we don't want.
- **Kotlin + GraalVM Native** — best Java interop (relevant for SAST
  Java), but build complexity and slower binaries outweigh the gain.

### Architecture: **Clean Architecture with DDD building blocks**

- Four layers: `domain`, `application`, `infrastructure`, `interfaces`.
- Strict dependency rule — arrows point inward; enforced by `depguard`.
- DDD vocabulary: aggregates (Finding, Scan, GatePolicy), Value Objects,
  Domain Services, Domain Events.
- Ports & Adapters at the application/infrastructure boundary.

Why this matters for Cortex specifically:

- Scanners and publishers are inherently pluggable. Ports & Adapters is
  the textbook fit.
- The Quality Gate is the most reused, most tested concept; isolating
  it as a pure domain service prevents accidental coupling to YAML,
  HTTP or the file system.
- SARIF parsing, git wrangling, HTTP retries, file I/O — all swappable
  details that should never leak into the gate's logic.

### Style: **Functional discipline within Go**

Go is not a functional language, but the domain can still be written
in a functional style:

- Pure functions, no globals, no side effects in `internal/domain/...`.
- Immutable value objects; aggregates return new instances on change.
- `Option[T]` and `Result[T, E]` via `samber/mo` — no `nil`-as-meaning,
  no panics.
- Pipelines via `samber/lo` for `Map`/`Filter`/`Reduce` over slices.
- Side effects pushed to the edges (`infrastructure`).

The linter enforces this:

- `depguard` blocks `net/http`, `os`, `database/sql` from `domain`.
- `forbidigo` blocks `panic` and `fmt.Print*` in production code.
- `exhaustive` enforces exhaustive switches on sum-type-like enums.

## Consequences

**Positive**

- Adding a new scanner / publisher is a localized change — new package
  implementing one interface.
- The Quality Gate is testable as a pure function; no fixtures, no
  mocks, blazing fast tests.
- Distribution is trivial: one binary per platform, one Docker image
  with the external scanners preinstalled.
- The domain is portable: if we ever want to embed Cortex in another
  Go service, the domain has no I/O to refactor.

**Negative**

- Go's lack of sum types and pattern matching makes some domain code
  more verbose than the equivalent in Rust or Kotlin.
- FP discipline requires culture: the linter helps, but reviewers must
  enforce immutability in code review.
- DDD on a CLI tool can feel heavy. Mitigation: apply DDD only where
  it pays off (aggregates with non-trivial invariants), and keep
  utility code plainly procedural.

## Follow-ups

- ADR-0002: SARIF as the canonical interchange format.
- ADR-0003: C# scanner choice (Security Code Scan vs SonarAnalyzer vs CodeQL).
- ADR-0004: Quality Gate evaluation semantics (sets vs streams,
  baseline comparison strategy).
