# ADR 0002 — SARIF v2.1.0 as the canonical interchange format

* **Date:** 2026-05-15
* **Status:** Accepted

## Context

Cortex aggregates output from many heterogeneous scanners. Each has its
own native format: Semgrep JSON, Bandit JSON, ESLint plain text,
SpotBugs XML, gosec JSON, Gitleaks JSON.

If the engine reasons in these native formats, every new scanner forces
changes throughout the codebase (parsing, deduplication, gate logic,
publishers). That violates Open/Closed.

## Decision

Adopt **SARIF v2.1.0** (OASIS standard) as the single internal format
for results. Every scanner adapter is responsible for producing SARIF,
either by invoking the tool with a SARIF formatter or by translating
native output to SARIF in the adapter.

The application layer and the domain reason only in SARIF-derived
domain types (`Finding`). Publishers consume the merged SARIF.

## Rationale

- **Industry standard.** GitHub Code Scanning, GitLab Security
  Dashboard, Azure DevOps, DefectDojo, KorvLabs and most modern SAST
  tools speak SARIF natively.
- **Schema-versioned.** Stable JSON Schema, easy to validate at the
  boundary.
- **Rich enough.** Locations, fingerprints, rule metadata, suppressions,
  and tool-specific properties all fit.
- **Decoupling.** Replacing Semgrep with CodeQL is a one-adapter change.

## Consequences

**Positive**
- Adding scanners = wrap them so their output is SARIF; nothing else
  changes.
- Publishers can mostly forward SARIF as-is.
- Cross-tool deduplication has a single canonical anchor: `(ruleId,
  artifact location, region)`.

**Negative**
- Some scanners (ESLint pre-formatter, SpotBugs) require an extra
  conversion step.
- SARIF is verbose; we ship a normalization helper to keep parsing
  cheap.

## Implementation pointer

`internal/infrastructure/sarif/` wraps `github.com/owenrumney/go-sarif`
and maps `sarif.Result` → `domain.finding.Finding`.
