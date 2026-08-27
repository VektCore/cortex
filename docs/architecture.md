# Cortex Architecture

## 1. Goals

Cortex is a multi-language SAST engine optimized to live inside CI/CD
pipelines. Its job is summarized in five verbs:

1. **Detect** which languages are in the repo.
2. **Scan** the code with the right tools.
3. **Aggregate + deduplicate** results into a single SARIF.
4. **Verify** them against a declarative Quality Gate.
5. **Publish** results to multiple destinations.

Anything that doesn't serve those five verbs does not belong in Cortex.

## 2. Layered design (Clean Architecture)

```
                 ┌──────────────────────────────────────┐
                 │  interfaces/cli (cobra) · httpapi    │  ← primary adapters
                 └──────────────────┬───────────────────┘
                                    │ DTOs
                 ┌──────────────────▼───────────────────┐
                 │   application/usecases · services    │  ← use cases
                 │   application/ports (interfaces)     │
                 └──────────────────┬───────────────────┘
                                    │ domain types only
                 ┌──────────────────▼───────────────────┐
                 │            internal/domain           │  ← pure logic
                 │   finding · scan · gate · ruleset    │
                 └──────────────────────────────────────┘
                                    ▲
                                    │ implements ports
                 ┌──────────────────┴───────────────────┐
                 │   internal/infrastructure            │  ← secondary adapters
                 │   scanners · publishers · sarif · …  │
                 └──────────────────────────────────────┘
```

**Dependency rule**: arrows always point inward. `infrastructure` knows
about `domain`, never the reverse. The rule is enforced statically by
`depguard` in `.golangci.yml`.

## 3. DDD building blocks

| Concept | Where | Notes |
|---|---|---|
| **Aggregate roots** | `domain/finding`, `domain/scan`, `domain/gate` | Each owns its invariants. |
| **Value Objects** | Inside each aggregate package | Immutable, equality by value. |
| **Domain Services** | `domain/*/services.go` | Pure functions: `Deduplicate`, `Evaluate`, `Compare`. |
| **Domain Events** | `domain/*/events.go` | Emitted by aggregates; consumed in app layer. |
| **Repositories** | Interfaces in `application/ports`; impls in `infrastructure` | Persistence is plug-in. |
| **Use Cases** | `application/usecases` | One per file; thin coordinators. |
| **Ports** | `application/ports` | Small, focused (ISP). |
| **Adapters** | `infrastructure/*` | Implement ports. Replaceable. |

## 4. Functional discipline

Although Go is not a pure FP language, Cortex's domain follows FP
conventions:

- **Pure functions** — no I/O, no globals, deterministic output.
- **Immutability** — aggregates return new instances, never mutate.
- **`Option[T]` / `Result[T, E]`** via `samber/mo` — no `nil` returns
  with hidden meaning, no panics in business code.
- **Composable pipelines** — `samber/lo` for `Map`, `Filter`,
  `Reduce` over slices of value objects.
- **Side effects at the edges** — all I/O lives in `infrastructure`.

The linter actively forbids `panic`, `fmt.Print*` (outside `cmd/` and
`interfaces/cli`), and imports of `net/http`, `os`, `database/sql` from
the `domain` layer.

## 5. Extending Cortex

Adding a new scanner is a self-contained operation:

1. Create `internal/infrastructure/scanners/<name>/`.
2. Implement `ports.Scanner`:
   ```go
   type Scanner interface {
       Name() ScannerName
       Languages() []shared.Language
       Scan(ctx context.Context, req ScanRequest) Result[ScanOutput]
   }
   ```
3. Register in `scanners/registry.go`.
4. Add a YAML key in `.cortex.yaml`'s `scanners:` section.
5. Add tests in `test/integration/scanners/<name>_test.go`.
6. If the adapter changes architecture, add an ADR.

The same pattern applies to `Publisher` and `Notifier` ports.

## 6. SARIF as canonical format

Cortex never reasons in "Semgrep findings" or "Bandit findings". Every
scanner adapter produces SARIF v2.1.0, parsed into domain `Finding`
value objects by `infrastructure/sarif`. Every publisher accepts SARIF.

This decouples the engine from the lifecycle of any specific tool:
swap Semgrep for CodeQL and the rest of Cortex doesn't notice.

## 7. Quality Gate

The gate is a pure function:

```
Evaluate : (Policy, []Finding) → Verdict
```

`Verdict` is a sum type — `Pass` or `Fail{reasons}`. The CLI translates
the verdict into an exit code that CI uses to block merges.

Baseline support means the gate sees only *new* findings vs a reference
point (typically `main`), which is the same model SonarQube and Snyk
use. This prevents "boiling-frog" repositories where legacy debt blocks
unrelated PRs.

## 8. Distribution

- Single static binary (`make build`).
- Multi-arch via release matrix (linux/darwin/windows × amd64/arm64).
- Docker image with all supported scanner binaries preinstalled.
- GitHub Action wrapper (`uses: vektcore/cortex-action@v1`).
- GitLab CI / Jenkins / Azure Pipelines templates.

## 9. Non-goals (explicit)

- Cortex is **not** a vulnerability database — that lives in publishers
  like KorvLabs.
- ~~Cortex is **not** a long-running service~~ — **revised 2026-08-27.** It is
  now both: a CLI invoked per run, and `cortex serve`, an HTTP API where the
  engine is deployed once and clients submit repositories with an API key.
  The reason is deployment economics, not architecture: asking every client to
  install seven scanners in their own CI is what stops adoption. The layering is
  unchanged — `interfaces/httpapi` is a second primary adapter beside
  `interfaces/cli`, both driving the same use cases through `internal/bootstrap`,
  and neither holding business logic.
- Cortex is **not** an LLM — enrichment is delegated to KorvLabs or any
  publisher that supports it.
- Cortex does **not** ship its own rules — it delegates rule authorship
  to upstream scanners (Semgrep, Bandit, …).
