# Extending Cortex

This guide walks through the three most common extensions: a new
**scanner**, a new **publisher**, and a new **language**.

## Adding a new Scanner

1. **Create the package.**
   ```
   internal/infrastructure/scanners/<name>/
       scanner.go     # implements ports.Scanner
       parser.go      # tool-specific output → SARIF (if not native SARIF)
       config.go      # struct for .cortex.yaml options
       scanner_test.go
   ```

2. **Implement the port.** Signatures live in
   `internal/application/ports/scanner.go`. Keep `Scan` pure on its
   inputs: the only side effect should be invoking the external tool.

3. **Register.** Add the constructor to `scanners/registry.go`.

4. **Configure.** Document the scanner's YAML keys in
   `.cortex.example.yaml` and in `docs/scanners/<name>.md`.

5. **Test.**
   - Unit-test the parser with golden files.
   - Add an integration test that invokes the real tool inside a Docker
     container (`test/integration/scanners/<name>_test.go`).
   - Add fixtures to `test/fixtures/kassandra-sast-demo/<language>/`
     that the scanner is expected to flag.

6. **Document.** If the scanner introduces a new dependency, new
   licence implications, or alters the architecture, add an ADR.

## Adding a new Publisher

1. **Create the package** under
   `internal/infrastructure/publishers/<name>/`.
2. **Implement `ports.Publisher`.** A publisher receives a merged SARIF
   document plus the scan's metadata; it returns either success or a
   typed error. Retries, backoff and circuit breaking are the
   publisher's responsibility.
3. **Register** in `publishers/registry.go`.
4. **Document** the YAML schema.
5. **Test** with a local mock server.

## Adding a new Language

1. Add the entry to `internal/domain/shared/language.go`.
2. Extend
   `internal/infrastructure/language_detection/detector.go` with the
   manifest / extension rules.
3. Wire at least one scanner that supports the new language.
4. Add a fixture under `test/fixtures/kassandra-sast-demo/<language>/`.

## Coding standards

- All new code must obey the Clean Architecture rules — the linter
  rejects forbidden imports at PR time.
- Domain code is pure. No `panic`, no `fmt.Print*`, no `os`/`net/http`
  imports.
- Use `samber/mo` for `Option[T]` and `Result[T, E]`. Never return
  `nil, nil`; never return `nil` for an "absent" value.
- Tests use `testify/require` (fail-fast assertions) and `testify/mock`
  for ports. Keep table-driven where possible.

## Project rituals

- One ADR per architectural decision. Numbered sequentially in
  `docs/adr/`.
- Conventional Commits (`feat:`, `fix:`, `chore:`…).
- PRs run the full CI: lint, test (matrix), govulncheck, build matrix,
  E2E against the kassandra-sast-demo fixture.
