#!/usr/bin/env bash
#
# bench.sh — run Cortex against a list of real repositories.
#
# Each repository is cloned by Cortex itself (scan accepts a git URL), scanned,
# gated and reported into its own directory under bench/, with its own
# vulnerability state. Keeping state per repository matters: a single shared
# .cortex/state.json would make every finding of repo B look "new" and every
# finding of repo A look "resolved" on the next run.
#
#   scripts/bench.sh                          # every repo in scripts/bench-repos.txt
#   scripts/bench.sh -f my-repos.txt          # a different list
#   scripts/bench.sh github.com/org/repo …    # ad-hoc targets, no list file
#   scripts/bench.sh -o /tmp/bench            # somewhere other than ./bench
#
# Exit code: 0 when every repository was scanned (whatever the gate said),
# 1 when at least one scan failed outright.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

LIST="scripts/bench-repos.txt"
OUT_ROOT="bench"
CONFIG="scripts/bench.cortex.yaml"

# macOS ships bash 3.2, where an empty array under `set -u` is an "unbound
# variable". Hence the ${arr[@]+…} guards and the explicit counter.
TARGETS=()
n_targets=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--file)    LIST="$2"; shift 2 ;;
    -o|--out)     OUT_ROOT="$2"; shift 2 ;;
    -c|--config)  CONFIG="$2"; shift 2 ;;
    -h|--help)    sed -n '2,20p' "$0"; exit 0 ;;
    -*)           echo "unknown flag: $1" >&2; exit 2 ;;
    *)            TARGETS+=("$1"); n_targets=$((n_targets + 1)); shift ;;
  esac
done

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

# gosec installs into GOPATH/bin, which is not on everyone's PATH; without this
# every Go repository silently loses its Go-specific scanner.
if command -v go >/dev/null 2>&1; then
  export PATH="$PATH:$(go env GOPATH)/bin"
fi

# ESLint resolves plugins and formatters from inside the project being linted.
# Foreign repos have neither installed, so point the resolver at the global
# install (the same thing the Docker image bakes in).
if command -v npm >/dev/null 2>&1; then
  NPM_GLOBAL="$(npm root -g 2>/dev/null)"
  if [[ -d "${NPM_GLOBAL:-}" ]]; then
    export CORTEX_ESLINT_PLUGINS_DIR="${CORTEX_ESLINT_PLUGINS_DIR:-$NPM_GLOBAL}"
    if [[ -d "$NPM_GLOBAL/@microsoft/eslint-formatter-sarif" ]]; then
      export CORTEX_ESLINT_FORMATTER="${CORTEX_ESLINT_FORMATTER:-$NPM_GLOBAL/@microsoft/eslint-formatter-sarif}"
    fi
  fi
fi

CORTEX="$REPO_ROOT/bin/cortex"
if [[ ! -x "$CORTEX" ]]; then
  echo "building bin/cortex…"
  make build >/dev/null || { echo "build failed" >&2; exit 1; }
fi

# Report which scanners are actually usable before spending minutes finding out.
echo "scanner availability:"
for tool in semgrep bandit gosec gitleaks eslint osv-scanner trivy; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf '  %-14s %s\n' "$tool" "$(command -v "$tool")"
  else
    printf '  %-14s MISSING — repos needing it lose that coverage\n' "$tool"
  fi
done
echo

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

if [[ $n_targets -eq 0 ]]; then
  [[ -f "$LIST" ]] || { echo "no repo list at $LIST" >&2; exit 2; }
  while IFS= read -r line; do
    line="${line%%#*}"
    line="$(echo "$line" | xargs)"
    [[ -z "$line" ]] && continue
    TARGETS+=("$line")
    n_targets=$((n_targets + 1))
  done < "$LIST"
fi

[[ $n_targets -eq 0 ]] && { echo "nothing to scan" >&2; exit 2; }

mkdir -p "$OUT_ROOT"
SUMMARY_CSV="$OUT_ROOT/summary.csv"
echo "repo,ref,slug,scan_exit,gate_exit,gate,total,critical,high,medium,low,info,scanners_ok,scanners_skipped,seconds" > "$SUMMARY_CSV"

slugify() {
  echo "$1" | sed -e 's#^https\{0,1\}://##' -e 's#^git@##' -e 's#\.git$##' \
             | tr ':/' '__' | tr -cd 'A-Za-z0-9._-'
}

failures=0

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

for entry in ${TARGETS[@]+"${TARGETS[@]}"}; do
  url="$(echo "$entry" | awk '{print $1}')"
  ref="$(echo "$entry" | awk '{print $2}')"
  slug="$(slugify "$url")"
  dir="$OUT_ROOT/$slug"
  mkdir -p "$dir"

  ref_args=()
  [[ -n "$ref" ]] && ref_args=(--ref "$ref")
  ref_display="${ref:--}"   # an empty field would shift every column right

  echo "═══ $url${ref:+ @ $ref}"
  started=$SECONDS

  # Each repository reconciles against its own history, never another's. The
  # path has to be absolute (Cortex may run with a different cwd) but an
  # already-absolute -o must not be prefixed, or the tree lands inside the repo.
  case "$dir" in
    /*) state_path="$dir/state.json" ;;
    *)  state_path="$REPO_ROOT/$dir/state.json" ;;
  esac
  export CORTEX_STATE_PATH="$state_path"

  "$CORTEX" -c "$CONFIG" scan "$url" ${ref_args[@]+"${ref_args[@]}"} --output "$dir" \
    > "$dir/scan.log" 2>&1
  scan_exit=$?

  tail -n 20 "$dir/scan.log" | sed 's/^/    /'

  if [[ $scan_exit -ne 0 || ! -f "$dir/scan.sarif" ]]; then
    echo "    SCAN FAILED (exit $scan_exit) — see $dir/scan.log"
    echo "$url,$ref_display,$slug,$scan_exit,-,scan-failed,-,-,-,-,-,-,0,-,$((SECONDS - started))" >> "$SUMMARY_CSV"
    failures=$((failures + 1))
    echo
    continue
  fi

  # The gate is evaluated separately so its exit code is observable per repo
  # instead of ending the whole bench.
  "$CORTEX" -c "$CONFIG" verify "$dir/scan.sarif" > "$dir/verify.log" 2>&1
  gate_exit=$?
  case $gate_exit in
    0) gate="pass" ;;
    1) gate="FAIL" ;;
    *) gate="error($gate_exit)" ;;
  esac

  "$CORTEX" -c "$CONFIG" report "$dir/scan.sarif" --format markdown \
    --output "$dir/report.md" > /dev/null 2>&1
  "$CORTEX" -c "$CONFIG" report "$dir/scan.sarif" --format json \
    --output "$dir/report.json" > /dev/null 2>&1

  # Scanners that could not run are the bench's blind spots — surface them
  # rather than letting a partial scan look like a clean one.
  skipped="$(awk '/^skipped [0-9]+ scanner/ {print $2; exit}' "$dir/scan.log")"
  skipped="${skipped:-0}"

  # Positive evidence: how many scanners actually produced a document. "0 skipped"
  # alone would look identical whether five tools ran or one did.
  scanners_ok=$(find "$dir" -maxdepth 1 -name '*.sarif' \
    ! -name 'scan.sarif' ! -name 'scan.raw.sarif' | wc -l | tr -d ' ')

  counts="$(python3 - "$dir/report.json" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as fh:
        doc = json.load(fh)
except Exception:
    print("0,0,0,0,0,0"); raise SystemExit
by = doc.get("by_severity", {}) or {}
order = ["critical", "high", "medium", "low", "info"]
print(",".join([str(doc.get("total", 0))] + [str(by.get(k, 0)) for k in order]))
PY
)"

  elapsed=$((SECONDS - started))
  echo "    gate: $gate   findings: ${counts%%,*}   scanners: $scanners_ok ran, $skipped skipped   ${elapsed}s"
  echo "$url,$ref_display,$slug,$scan_exit,$gate_exit,$gate,$counts,$scanners_ok,$skipped,$elapsed" >> "$SUMMARY_CSV"
  echo
done

unset CORTEX_STATE_PATH

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

SUMMARY_MD="$OUT_ROOT/summary.md"
{
  echo "# Cortex bench — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "| repo | gate | total | crit | high | med | low | info | skipped | secs |"
  echo "|---|---|--:|--:|--:|--:|--:|--:|--:|--:|"
  tail -n +2 "$SUMMARY_CSV" | awk -F, '{
    printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
      $1, $6, $7, $8, $9, $10, $11, $12, $13, $14
  }'
} > "$SUMMARY_MD"

echo "───────────────────────────────────────────────"
column -s, -t "$SUMMARY_CSV" 2>/dev/null || cat "$SUMMARY_CSV"
echo
echo "per-repo artifacts: $OUT_ROOT/<slug>/{scan.sarif,report.md,report.json,scan.log,state.json}"
echo "summary: $SUMMARY_MD"

[[ $failures -gt 0 ]] && exit 1
exit 0
