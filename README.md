# Cortex

> Multi-language SAST engine designed to run as a CI/CD pipeline step.
> Orchestrates many scanners, normalizes everything to SARIF, applies a
> declarative Quality Gate, and publishes results to multiple destinations.

[![CI](https://github.com/vektcore/cortex/actions/workflows/ci.yml/badge.svg)](https://github.com/vektcore/cortex/actions/workflows/ci.yml)

## What it does

```
                  ┌─────────────────────────────────────────────────┐
                  │                    cortex pipeline              │
                  └─────────────────────────────────────────────────┘
                                          │
        ┌─────────────┬─────────────┬─────┴─────┬─────────────┬─────────────┐
        ▼             ▼             ▼           ▼             ▼             ▼
    Semgrep       Bandit        ESLint      SpotBugs        gosec      Gitleaks
    (multi)      (Python)       (JS/TS)      (Java)         (Go)      (secrets)
        │             │             │           │             │             │
        └─────────────┴─────────────┴─────┬─────┴─────────────┴─────────────┘
                                          ▼
                              ┌───────────────────────┐
                              │   SARIF Aggregator    │
                              │   + Deduplication     │
                              └───────────┬───────────┘
                                          ▼
                              ┌───────────────────────┐
                              │     Quality Gate      │  ← exit code
                              │  (declarative rules)  │     gates merge
                              └───────────┬───────────┘
                                          ▼
                  ┌───────────────────────────────────────────────┐
                  │      Publishers (KorvLabs, GitHub, …)         │
                  └───────────────────────────────────────────────┘
```

## Supported languages (MVP)

| Language | Scanners | Status |
|---|---|---|
| Dependencies (any) | osv-scanner · Trivy | working |
| Python | Semgrep · Bandit | working |
| JavaScript / TypeScript | Semgrep · ESLint-security | working |
| Java | Semgrep · SpotBugs + find-sec-bugs | Semgrep working; SpotBugs needs a Maven build |
| Go | Semgrep · gosec | working |
| C# / .NET | Semgrep · Security Code Scan | Semgrep working; SCS needs the analyzer in the csproj |
| Secrets (any) | Gitleaks | working |

## Quick start

```bash
# Install the engine
go install github.com/vektcore/cortex/cmd/cortex@latest

# Run inside a repository
cd your-project
cortex detect                 # which languages and scanners apply here
cortex pipeline               # scan → aggregate → verify → report → publish
echo "exit code: $?"          # 0 = gate passed, 1 = gate failed
```

Cortex drives external scanners; it never bundles them. Install the ones you
need — a missing binary is a non-fatal, per-scanner error, and `cortex detect`
flags it:

```bash
pipx install semgrep
pipx install bandit && pipx inject bandit bandit-sarif-formatter   # SARIF output
go install github.com/securego/gosec/v2/cmd/gosec@latest
brew install gitleaks                                             # or the GitHub release
npm i -g eslint@8 eslint-plugin-security @microsoft/eslint-formatter-sarif
```

### Scanning a remote repository

Any command that takes a target accepts a repository URL instead of a path.
Cortex clones it (shallow by default) into a temporary directory, scans it, and
cleans up:

```bash
cortex detect github.com/my-org/api
cortex scan   github.com/my-org/api --ref main
cortex scan   git@github.com:my-org/api.git          # uses your SSH agent
cortex pipeline https://gitlab.com/my-org/api.git --ref v2.1.0
```

Private repositories over HTTPS read a token from `CORTEX_GIT_TOKEN`,
`GITHUB_TOKEN` or `GITLAB_TOKEN`. The token is injected into the clone URL and
never printed — errors show the URL redacted.

### CI: GitHub Actions

The repository ships a composite action that runs the pipeline, publishes the
findings to the Security tab, writes the report into the job summary, and fails
the job when the gate fails:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: vektcore/cortex@v1
    with:
      path: .
      fail-on-gate: true
      upload-sarif: true
```

Ready-to-copy workflows live in [`docs/examples/`](docs/examples/):

| File | What it does |
|---|---|
| `github-actions-sast.yml` | gate every PR, upload SARIF to Code Scanning |
| `github-actions-no-docker.yml` | same, installing the scanners on the runner instead of using the image |
| `github-actions-scan-external-repo.yml` | scheduled sweep of several repositories, cloned by Cortex itself |

Uploading to Code Scanning is done by `github/codeql-action/upload-sarif`, so
findings appear inline on the pull request without needing a Cortex publisher.

### Docker

The image carries the engine plus semgrep, bandit, gosec, gitleaks and
eslint-security, so nothing has to be installed on the host:

```bash
docker build -t cortex:dev .

# Mount /state to keep the vulnerability history between runs.
docker run --rm \
  -v "$PWD":/src:ro \
  -v cortex-state:/state \
  -v "$PWD/results":/results \
  cortex:dev scan /src -c /etc/cortex/cortex.yaml --output /results
```

The image carries semgrep, bandit, gosec, gitleaks, eslint-security,
osv-scanner and trivy (1.1 GB). Without the `/state` mount the scan still
works — it just forgets between runs, and says so.

SpotBugs and Security Code Scan are deliberately absent: both need a project
build (`mvn package`, `dotnet build`) rather than a binary.

## Vulnerability tracking

A scan is an observation; a vulnerability is something a team manages. Cortex
keeps the second between runs, so the same 4000 findings are not re-triaged
forever:

```bash
cortex scan .                     # reconciles against what was already known
#   since the last scan: 3 new, 1 reopened, 12 resolved
cortex status                     # open / triaged / resolved, regressions, oldest debt
cortex triage a1b2c3d4 --status false_positive --reason "test fixture, not shipped"
cortex triage a1b2c3d4 --status accepted_risk  --reason "legacy" --expires 2026-12-31
```

Identity is a **three-level fingerprint** — exact line, file content, enclosing
symbol — matched in cascade. A decision therefore survives an edit above the
finding, and survives the function being moved to another file. Ambiguity is
never resolved by guessing: two weaknesses that share a symbol fall back to the
precise level rather than inheriting each other's triage.

Lifecycle: `detected → confirmed | false_positive | accepted_risk → resolved`,
and `resolved → reopened` when a fixed weakness comes back — a regression, which
the scan reports explicitly. An `accepted_risk` requires an expiry date; when it
runs out the finding returns to the queue.

## Server mode: clients connect with an API key

The other way round from a CI plugin. Deploy Cortex once — the image carries the
scanners — and clients submit repositories instead of installing seven tools:

```bash
cortex serve -c server.yaml
```

```bash
# A client asks for an analysis. No scanner, no config, no Cortex on their side.
curl -X POST https://sast.example.com/api/v1/analyses \
  -H "Authorization: Bearer $CLIENT_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"repository":"github.com/acme/api","ref":"main","project":"acme-api"}'
# → 202 {"id":"4fa7f2ade127d225","status":"queued", ...}

# Then poll it.
curl -H "Authorization: Bearer $CLIENT_KEY" \
  https://sast.example.com/api/v1/analyses/4fa7f2ade127d225
```

```json
{
  "status": "completed",
  "gate": "passed",
  "findings": 2,
  "by_severity": { "medium": 2 },
  "new_findings": 0,
  "known_before": 2,
  "scanners_ran": 3,
  "requested_by": "acme"
}
```

`new_findings` against `known_before` is the number a returning client actually
reads, and `scanners_ran` is there so a run where four of five tools failed
cannot pass for a clean one.

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/analyses` | analyse a repository (Cortex clones it) |
| `GET /api/v1/analyses` | list, newest first, `?project=` and `?limit=` |
| `GET /api/v1/analyses/{id}` | status, gate verdict, what changed |
| `GET /api/v1/analyses/{id}/sarif` | the findings, as SARIF |
| `POST /api/v1/webhooks/github` | GitHub push webhook: scan on every push |
| `POST /api/v1/scans` | ingest SARIF from a client's own CI |
| `GET`/`PUT /api/v1/projects/{p}/vulnerabilities` | the tracked state |
| `GET /healthz` | liveness, unauthenticated |

Everything else requires `Authorization: Bearer <api key>`, and the server
**refuses to start without at least one key**: it can clone repositories, so an
open instance is not a sensible default. Keys are compared in constant time,
never logged, and never echoed in an error — each analysis records the client's
*name* instead.

Credentials for private repositories live on the server (`CORTEX_GIT_TOKEN`,
`GITHUB_TOKEN`, `GITLAB_TOKEN`, or an SSH agent), so clients never send tokens
over the API.

### Connecting a repository: nothing installed in it

A repository is connected by pointing its push webhook at the server. No
workflow, no config file, no scanners on their side — the server clones the
repository itself.

In the repository's **Settings → Webhooks → Add webhook**:

| Field | Value |
|---|---|
| Payload URL | `https://sast.example.com/api/v1/webhooks/github` |
| Content type | `application/json` |
| Secret | the value of `server.webhook_secret` |
| Events | Just the push event |

The endpoint authenticates with GitHub's HMAC signature over the body rather
than an API key, because GitHub cannot send a bearer token. **With no secret
configured the endpoint stays closed**: an unauthenticated webhook lets anyone
who finds the URL make the server clone repositories on demand.

Only the branch of record is analysed — the repository's default branch, or the
list in `server.webhook_branches`. Analysing every feature branch multiplies the
work without changing the number anybody looks at.

Deploy it with [`docs/examples/docker-compose.server.yml`](docs/examples/docker-compose.server.yml)
and [`docs/examples/server.yaml`](docs/examples/server.yaml). Put a TLS-terminating
proxy in front: the API keys travel in a header.

### Managed mode: keeping the history on a server

Committing `.cortex/state.json` is right for a repository you own. It does not
work when you analyse someone else's: their repository is not going to carry
your state document, and the triage has to be visible to whoever runs the
service rather than to whoever clones the repo.

Point the state at an API instead, and the same history works for any number of
repositories:

```yaml
state:
  enabled: true
  backend: remote            # "file" (default) or "remote"
  remote:
    url: https://api.korvlabs.example
    token: ${KORVLABS_API_KEY}
    project: acme-api        # which project's history to reconcile against
```

The wire format is byte-identical to the file one, so a project can switch
backends without a migration. A project with no history yet answers 404, which
Cortex reads as a first scan — never as an error.

The server has to answer three calls. `scripts/mock-platform.py` implements them
so the mode can be exercised before a platform exists:

| Call | Purpose |
|---|---|
| `POST /api/v1/scans` | ingest the merged SARIF (the publisher already sends it) |
| `GET  /api/v1/projects/<id>/vulnerabilities` | the project's tracked state |
| `PUT  /api/v1/projects/<id>/vulnerabilities` | replace it after a scan |

```bash
scripts/mock-platform.py --port 8790 --token dev-token   # in one terminal
cortex scan github.com/acme/api -c managed.yaml          # in another
```

Run it twice against unchanged code and the second pass reports `0 new`: the
memory is on the server, not in the repository.

### Gating new code, not the whole repository

An absolute gate ("zero criticals") is unadoptable for a repository that already
carries thousands of findings. Two narrower scopes are:

```bash
cortex verify results/scan.sarif --new-only                  # never seen in any scan
cortex verify results/scan.sarif --changed-since origin/main # on lines this branch touched
```

Both can be combined, and triaged-away findings are excluded either way.

## Beyond code: dependencies, dead code, live secrets

| What | How |
|---|---|
| **Dependency CVEs (SCA)** | `osv` and `trivy` adapters. Most exploitable CVEs live in dependencies, not in code the team wrote |
| **Reachability** | each finding is labelled reachable / unreachable / unknown; dead-code findings drop one severity step and are never escalated back |
| **Live secret verification** | `scanners.gitleaks.options.verify: "true"` — a working credential goes to critical, a revoked one to low. Opt-in: it sends the credential to its own provider in a read-only call |

## Configuration (`.cortex.yaml`)

```yaml
version: "1"

scanners:
  semgrep:
    enabled: true
    timeout: 10m
    options: { config: auto }     # or p/security-audit, p/owasp-top-ten
  bandit:          { enabled: true }
  gosec:           { enabled: true }
  gitleaks:        { enabled: true }
  eslint_security: { enabled: true }
  spotbugs:           { enabled: false }   # needs a Maven build
  security_code_scan: { enabled: false }   # needs the analyzer in the csproj

gate:
  rules:
    - { name: no-critical, severity: critical, threshold: ">=1" }
    - { name: few-high,    severity: high,     threshold: ">5" }
    - { name: injection,   cwes: [CWE-89, CWE-78], threshold: ">=1" }

# Suppressed from the gate only — still reported and still in the SARIF.
ignore:
  - { rule_id: B101, path_prefix: tests/, reason: "asserts in tests", expires: "2026-12-31" }

publishers:
  filesystem: { enabled: true, output_dir: results/ }
  korvlabs:   { enabled: false, url: https://api.korvlabs.example, api_key: ${KORVLABS_API_KEY} }
```

Any value can be overridden by an environment variable: `CORTEX_` + the path
with dots replaced by underscores, e.g. `CORTEX_PUBLISHERS_KORVLABS_URL`.

[`.cortex.example.yaml`](.cortex.example.yaml) documents every key the loader
actually reads, plus the ones that are not wired yet.

## Architecture

Cortex follows Clean Architecture with strict DDD boundaries:

```
cmd/cortex/                  → entrypoint only
internal/
  domain/                    → pure business logic, no I/O
  application/               → use cases + ports
    ports/                   → interfaces (Scanner, Publisher, Notifier, …)
    usecases/                → ExecuteScan, ApplyGate, Publish, …
  infrastructure/            → adapters: scanners, publishers, notifiers, SARIF
  interfaces/cli/            → cobra commands
pkg/sdk/                     → public API (future plugin SDK)
test/fixtures/               → kassandra-sast-demo as canonical E2E fixture
```

The dependency rule is enforced by `.golangci.yml` (depguard linter).
See [`docs/architecture.md`](docs/architecture.md) and the ADRs in
[`docs/adr/`](docs/adr/) for the full reasoning.

## CLI

```
cortex detect      discover languages and applicable scanners
cortex scan        run all configured scanners in parallel (local path or git URL)
cortex aggregate   merge SARIF files, deduplicate findings
cortex verify      apply Quality Gate (exit 1 on failure)
cortex report      render a markdown / JSON / text summary
cortex publish     send results to configured destinations
cortex baseline    manage the baseline SARIF for differential gating
cortex pipeline    run the full chain in one shot
cortex status      tracked vulnerabilities: open, triaged, resolved, regressions
cortex triage      record a decision about a vulnerability
cortex version     show version information
```

## Development

```bash
make init          # install golangci-lint, govulncheck
make build         # build the binary into bin/cortex
make test          # unit tests with race + coverage
make lint          # golangci-lint with our strict policy
make test-e2e      # run E2E against test/fixtures/kassandra-sast-demo
make bench         # scan real repositories end to end (see below)
make help          # list all targets
```

### Bench: running against real repositories

The fixture proves the contract; it does not tell you how the engine behaves on
a real codebase. `scripts/bench.sh` points Cortex at a list of deliberately
vulnerable public repositories, letting the engine clone each one itself:

```bash
make bench                                   # everything in scripts/bench-repos.txt
./scripts/bench.sh github.com/org/repo       # one ad-hoc target
./scripts/bench.sh -f my-list.txt -o /tmp/b  # another list, another output dir
```

Every repository gets its own directory under `bench/<slug>/` with its SARIF,
`report.md`, `report.json`, the scan log and — importantly — **its own
`state.json`**. A single shared state would make every finding of the next
repository look new and every finding of the previous one look resolved, so the
runner exports `CORTEX_STATE_PATH` per target. Run it twice and the second pass
reports `0 new`, which is the vulnerability tracking working.

The run prints, and writes to `bench/summary.{csv,md}`, one row per repository:
gate verdict, findings by severity, **how many scanners actually produced
results**, how many were skipped, and the wall time. The scanner count is there
on purpose — a scan where four of five tools silently failed otherwise looks
just like a clean one.

`scripts/bench.cortex.yaml` is the config it uses: no absolute paths (ESLint's
global plugin directory is resolved at runtime), third-party directories
excluded, and the same gate as production.

## Status

**Working end-to-end.** `detect → scan → aggregate → verify → report → publish`
runs against a real repository, drives 5 scanners in parallel, normalizes
everything to SARIF, and gates on a declarative policy.

| Area | State |
|---|---|
| Domain (finding, scan, gate, fingerprinting, dedup, diff) | complete, unit-tested |
| Application (4 use cases + pipeline service, 9 ports) | complete, unit-tested |
| SARIF codec (parse · write · merge) | complete |
| Scanner adapters | semgrep, bandit, gosec, gitleaks, eslint-security verified against the fixture; spotbugs and security_code_scan written but need a project build |
| Finding precision | 100% of findings carry a CWE; severity escalation by weakness class; stable relative paths; lossless SARIF round-trip |
| Own rule pack | `rules/` — path traversal, SSRF, C# XXE, which the registry set misses |
| Fixture contract | `make test-e2e` validates all 21 declared vulnerabilities |
| CLI | all 9 commands implemented |
| Quality Gate + allowlist with expiry | complete |
| Baseline | `cortex baseline create/show` + `verify --baseline <file>`; generating a baseline from a git ref is not implemented |
| Publishers | filesystem, korvlabs. GitHub Code Scanning and GitLab Security not started |
| Notifiers (Slack, GitHub PR comment) | not started |
| Vulnerability lifecycle | persistent state, three-level fingerprint matching, triage with expiry, regression detection |
| New-code gating | `--new-only` (vs tracked state) and `--changed-since REF` (vs git diff lines) |
| SCA | osv-scanner and trivy adapters for dependency CVEs |
| Reachability | conservative dead-code analysis; labels and demotes, never escalates back |
| Secret verification | live-credential check for GitHub, Stripe, OpenAI, Slack, SendGrid |
| Remote targets | any command takes a git URL; shallow clone, `--ref`, token auth |
| CI | composite GitHub Action + example workflows; SARIF upload via codeql-action |
| Lint policy | `make lint` green: 0 issues under the strict policy (depguard, complexity ≤ 12, functions ≤ 80 lines) |
| Distribution | Dockerfile + GHCR publish workflow. No goreleaser, no Homebrew tap yet |

The design decisions and their reasoning live in [docs/adr/](docs/adr/) and
[docs/architecture.md](docs/architecture.md).

## License

MIT
