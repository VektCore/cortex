# ADR 0003 — C# / .NET scanner: Security Code Scan

* **Date:** 2026-05-15
* **Status:** Accepted

## Context

C# is part of the MVP language matrix. We needed a SAST scanner that:

- Emits SARIF (or can be wrapped to do so).
- Detects the OWASP top issues in .NET code: SQLi, XSS, XXE, path
  traversal, hardcoded secrets, weak crypto, insecure deserialization.
- Is open-source and self-hostable (no proprietary licence required
  for commercial use).
- Has reasonable false-positive rates.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **Security Code Scan** | Roslyn-based (AST, not regex), MIT, SARIF support, low FP | Smaller community than SonarAnalyzer |
| **SonarAnalyzer.C#** | Comprehensive, well-maintained | Best results require SonarScanner + Sonar server |
| **CodeQL** | State-of-the-art, deep dataflow | Not OSS for commercial use |
| **Semgrep** | Already in the stack, multi-language | Weaker on C# than the dedicated tools |

## Decision

Use **Security Code Scan** as the dedicated C# scanner, with **Semgrep**
as a secondary cross-cutting scanner (consistent with every other
language in the MVP).

## Rationale

- Roslyn analyzers produce SARIF natively via `dotnet build` with the
  analyzer referenced.
- MIT licence — no commercial restrictions.
- AST-level analysis keeps FP low compared to regex-based tools.
- Adopting it now means the adapter pattern is validated against an
  IDE-style analyzer, not just CLI scanners.

## Consequences

- The Cortex Docker image must include .NET SDK 8 (~200 MB extra).
- The adapter invokes `dotnet build` with Security Code Scan
  referenced, then collects the generated SARIF — slower than a single
  CLI invocation, mitigated by NuGet/MSBuild caching in CI.

## Follow-ups

- Future ADR: optionally add SonarAnalyzer for repos that already use
  SonarQube, so customers don't pay analysis twice.
