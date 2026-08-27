# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Cortex is a multi-language SAST engine (Go, module `github.com/vektcore/cortex`) designed to run as a
CI/CD pipeline step: it detects languages, drives N external scanners in parallel, normalizes everything
to SARIF, applies a declarative Quality Gate whose verdict becomes the process exit code, and publishes
results. It is to KorvLabs what SonarScanner is to SonarQube — but deliberately platform-agnostic.

Cortex **never bundles scanners**. It shells out to semgrep, bandit, gosec, gitleaks, eslint, osv-scanner,
trivy, etc. A missing binary is a non-fatal per-scanner error.

## Commands

```bash
make init              # install golangci-lint + govulncheck, go mod download/tidy
make build             # binary → bin/cortex (injects version/commit/buildDate via ldflags)
make lint              # golangci-lint v2 under the strict policy; must stay at 0 issues
make test              # = test-unit: -race + coverage over ./internal/domain/... ./internal/application/...
make test-e2e          # builds, then runs ./test/e2e with -tags=e2e (needs scanners on PATH)
make test-integration  # real scanners + httptest platform, -tags=integration
make bench             # scans the real repos in scripts/bench-repos.txt (network; minutes)
make coverage          # opens the HTML coverage report
```

Running narrower:

```bash
go test ./internal/domain/finding/ -run TestFingerprint -v
go test -tags=e2e -run TestFixtureContract ./test/e2e/
go test -race ./internal/...          # what CI actually runs — wider than `make test`
```

`make test-integration` runs `test/integration/` with `-tags=integration`: real scanners and a real HTTP
server, no external network. It skips itself when no scanner is on PATH. `test/unit/` is empty and stays
that way — unit tests live next to the code.

Dogfooding the engine on itself:

```bash
./bin/cortex detect .            # which languages/scanners apply, and which binaries are missing
./bin/cortex pipeline .          # scan → aggregate → verify → report → publish
```

Running against real repositories (`scripts/bench.sh`, `make bench`): each target in
`scripts/bench-repos.txt` is cloned by Cortex itself and lands in `bench/<slug>/` with its own
SARIF, report and **its own `state.json`** — the runner exports `CORTEX_STATE_PATH` per repo
because one shared state would make each repo's findings look new and the previous repo's look
resolved. It uses `scripts/bench.cortex.yaml` (no absolute paths; ESLint's global plugin dir is
resolved at runtime from `npm root -g`, and `$(go env GOPATH)/bin` is added to PATH so gosec is
found). The summary records how many scanners actually produced results, not just how many were
skipped — a scan where four of five tools failed otherwise reads as a clean one.

This working copy **is now a git repository** (initialised 2026-08-27, one commit, no remote yet), so
`make build` stamps a real VERSION and the git-backed paths work. Two consequences of that change bit
already and are guarded now: Semgrep narrows a scan to git-tracked files and applies its own
`.semgrepignore` (see the scanner quirks), and `verify --changed-since` needs a ref that exists.

## Architecture

Clean Architecture with tactical DDD, four layers, dependencies pointing strictly inward:

```
cmd/cortex                  → main; calls cli.Execute, returns its exit code
internal/interfaces/cli     → cobra; one <verb>_cmd.go per command. Translation only, no logic.
internal/interfaces/httpapi → `cortex serve`: the API clients hit with a Bearer key. Second primary
                              adapter; same use cases, no logic of its own.
internal/bootstrap          → the object graph both adapters share (Registry/ExecuteScan/Pipeline/Store).
                              cli/container.go is now thin delegation to it.
internal/application        → ports/ (one interface per file), usecases/ (one per file), services/pipeline.go, dto/
internal/domain             → pure: finding, scan, gate, vulnerability, ruleset, shared
internal/infrastructure     → adapters implementing ports: scanners/<tool>/, publishers/, sarif/, state/,
                              git/, config/, symbols/, reachability/, secrets/, language_detection/
pkg/sdk                     → placeholder for a future public plugin SDK
```

The dependency rule is **statically enforced** by depguard in `.golangci.yml`, not by convention:
`domain` may not import application/infrastructure/interfaces, nor `net/http`, `os`, `database/sql`;
`application` may not import infrastructure or interfaces. Wiring a new adapter into the app layer means
adding a port, never an import.

Flow of one run (`services.Pipeline.Execute`): `ExecuteScan` (registry fan-out, parallel, per-scanner
failure isolated) → `AggregateFindings` (dedup, incl. cross-scanner) → `ApplyQualityGate` (optional
baseline) → `PublishResults` (fan-out to publishers). Gate failure is a `Verdict`, **not** an error — only
infrastructure failures return `Err`.

### Canonical format

Every scanner adapter emits SARIF v2.1.0; `infrastructure/sarif` parses it into `domain/finding.Finding`
value objects; every publisher consumes SARIF. Nothing in the engine reasons in "Semgrep findings".

### Vulnerability lifecycle

A scan is an observation; a vulnerability is state. `infrastructure/state` persists
`.cortex/state.json` (committable, so triage is reviewed like code) — or, with `state.backend: remote`,
an HTTP API (`state/remote.go`), which is what makes analysing a repository Cortex does not own viable:
someone else's repo will not carry our state file. Both backends write the same bytes, so a project can
switch without a migration; `scripts/mock-platform.py` implements the server side for local runs. Identity is a three-level cascade
fingerprint — exact line → file content → enclosing symbol — so a triage decision survives edits above the
finding and survives the function moving files. Statuses: `detected → confirmed | false_positive |
accepted_risk → resolved`, plus `resolved → reopened` (a reported regression). `accepted_risk` requires an
expiry.

## Non-negotiables

These are enforced by the linter or by tests; do not work around them.

- **No `panic`** outside tests/CLI; **no `fmt.Print*`** outside `cmd/` and `internal/interfaces/cli/`.
  Use `mo.Result[T]` for failure and `mo.Option[T]` for absence — never `nil, nil`, never a bare `nil`
  meaning "absent". Helpers: `shared.Ok/Err/Some/None`.
- **Aggregates are immutable**: unexported fields, accessors, transitions return a new instance. Copy the
  `with(mutate)` pattern in `domain/scan/scan.go` for any new aggregate.
- **Never call `time.Now()` in the domain** — inject `shared.Clock`. It is the only reason domain tests are
  deterministic.
- **Never merge ports.** If unsure whether to extend an existing port or add one, add one (ISP).
- **Don't touch the fingerprint's hash-input order** in `domain/finding/fingerprint.go`. It is what makes
  dedup, baseline and tracking comparable across runs; if it must change, version the algorithm
  (`FingerprintV1`/`V2`) rather than mutating it.
- **Pinned to Go 1.22** — no generic type aliases (1.24+). Reference `mo.Option[T]`/`mo.Result[T]`
  directly in signatures and re-export via constructor functions.
- **The fixture is vulnerable on purpose.** `test/fixtures/kassandra-sast-demo/` plus the CWE table in
  `test/fixtures/README.md` are the E2E contract — `test/e2e/contract_test.go` parses that table. Fixing a
  SQLi there breaks the build. The upstream original at
  `../kassandra-sast-demo-master/` is not ours to edit; only the copy under `test/fixtures/` is.
- **KorvLabs stays one publisher among several.** No KorvLabs-specific concepts (LLM enrichment,
  Exposures) in the domain. Closed decision — see HANDOFF.md §3.

The two deliberate lint exclusions, both commented in `.golangci.yml`: `gosec` G204 in
`infrastructure/{scanners,git}` (running a configured binary against a configured path is the product), and
`exhaustive` in tests.

## Adding a scanner

1. `internal/infrastructure/scanners/<name>/scanner.go` implementing `ports.Scanner`
   (`Name`, `SupportedLanguages`, `Available`, `Scan`). Copy `gosec/` as the reference shape: `New(codec,
   binary)`, binary defaulting to the tool name, subprocess + `codec.Parse`.
2. Register it in `cli/container.go`'s `buildRegistry` behind its `cfg.Scanners.<X>.Enabled` flag.
3. Add its config struct field in `infrastructure/config/config.go` and document the keys in
   `.cortex.example.yaml`.
4. Unit-test the parse path with golden files; add fixtures the scanner is expected to flag, and rows in
   `test/fixtures/README.md` if they're part of the contract.

`Publisher` and `Notifier` follow the same shape. Architecture-changing adapters get an ADR in `docs/adr/`.

## Scanner quirks learned the hard way

Do not "clean these up" back to the obvious version:

- **Semgrep** puts severity in `rule.defaultConfiguration.level`, not on the result. Ignore that and every
  finding collapses to `info` and the gate goes blind.
- **Semgrep inside a git repository** silently narrows the scan to tracked files and applies its own
  `.semgrepignore`, whose default list drops test directories. The adapter passes `--no-git-ignore` so the
  same code yields the same findings whether or not it is a checkout, and this repo ships a
  `.semgrepignore` that replaces that default list — without it, `test/fixtures/` is invisible and all 21
  contract rows fail. Keep it aligned with `exclude:` in `.cortex.yaml`.
- **`config: auto` is not reproducible**: Semgrep resolves the ruleset server-side from project metadata,
  so it requires their metrics enabled and can return a different set tomorrow. Configs here name rulesets
  explicitly (`p/security-audit,p/owasp-top-ten,p/secrets`) plus the local `rules/` pack.
- **Bandit** has no native SARIF — needs `bandit-sarif-formatter`; some results carry only
  `properties.issue_severity`.
- **Gitleaks** ≥8.28 dropped `detect`: use `gitleaks dir <path>` (working tree) or `gitleaks git` (history).
- **ESLint** with `--no-eslintrc` enables no rules, and without `parserOptions` parses as ES5. The adapter
  writes a temp eslintrc with the plugin's rules and `ecmaVersion: latest`; `plugin:security/recommended`
  from v4 is flat-config and eslintrc rejects it. Global plugin/formatter resolution needs absolute paths
  (`plugins_dir`, `formatter`, or `CORTEX_ESLINT_PLUGINS_DIR` / `CORTEX_ESLINT_FORMATTER`).
- **go-sarif v2.3.3**: `Properties` is a bare `map[string]interface{}` (no `Additional`, no `Tags`), and
  `sarif.New` takes `sarif.Version210`, not the schema URL. It also rejects two things real tools emit,
  which is why `sarif/parser.go` parses, and on failure re-parses a sanitized copy (`sanitizeSARIF`):
  osv-scanner's `"index": -1`, and **gosec's `taxonomies[].releaseDateUtc: "2021-03-15"`** — a date
  without a time, which SARIF permits. Either one otherwise costs that scanner's entire output.
- **osv-scanner exits 128** when the target has no manifest it recognises. That is an empty result, not a
  failure; treating it as one marked osv broken on every repo without a dependency file it can read.
- `spotbugs` and `security_code_scan` are written but unverified: both need a project build
  (`mvn package`, `dotnet build`) rather than a binary, and ship disabled.

## Config and exit codes

`.cortex.yaml` (see `.cortex.example.yaml` for every key the loader actually reads, including the not-yet-
wired ones). Any value is overridable by env: `CORTEX_` + path with dots as underscores, e.g.
`CORTEX_PUBLISHERS_KORVLABS_URL`. `ignore:` entries suppress from the *gate* only — findings stay in the
report and the SARIF.

Exit codes are a public contract with CI (`cli/root.go`): 0 ok, 1 gate failed, 2 config, 3 scanner,
4 publisher, 99 internal.

## Conventions

- Communicate with the user in **Spanish**; code, comments and identifiers in **English**. Technical
  design docs in this repo are Spanish (HANDOFF.md, PLAN.md), the ones aimed outward are English.
- Conventional Commits (`feat:`, `fix:`, `chore:`).
- `testify/require` for fail-fast assertions, table-driven where it fits. Shared fakes live in
  `usecases/fakes_test.go`.
- Import grouping is gci-enforced: stdlib, third-party, then `github.com/vektcore/cortex`.

## Where the rest of the state lives

- `HANDOFF.md`, `PLAN.md`, `docs/platform-ideas.md`, `docs/plan-plataforma.md` — internal working
  documents (Spanish). They are **gitignored**: they carry roadmap and commercial reasoning that does not
  belong in a public repository, so they exist only in the working copy. Read them before large changes.
- `docs/architecture.md`, `docs/extending.md`, `docs/adr/000{1,2,3}-*.md` — reasoning behind the layering,
  SARIF-as-canonical, and the C# scanner choice.
