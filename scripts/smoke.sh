#!/usr/bin/env bash
#
# smoke.sh — drive a running Cortex server through the whole client flow.
#
# The upload deployment is the one a client's pipeline actually blocks on: it
# packages the tree it is building, posts it, and stops the build when the
# verdict is negative. Nothing had ever exercised that path end to end, so the
# first time it ran for real was in somebody's pipeline. This script is that
# pipeline reduced to its assertions, to be run the moment a server comes up.
#
#   CORTEX_API_KEY=… scripts/smoke.sh --url https://sast.example.com
#   CORTEX_API_KEY=… scripts/smoke.sh --url … --path ../clean-repo --expect-pass
#
# What makes it a test rather than a demo: it fails on a *clean* result. Pointed
# at the vulnerable fixture, "0 findings, gate passed" does not mean the code is
# safe, it means no scanner ran. A server that passes everything is exactly the
# failure this exists to catch, and it is the one a happy-path check cannot see.
#
# Flags, each with an environment variable so CI can set it either way:
#
#   --url URL              CORTEX_URL            base URL of the server (required)
#   --api-key-env NAME     —                     env var holding the key
#                                                (default: CORTEX_API_KEY)
#   --api-key-file PATH    CORTEX_API_KEY_FILE   read the key from a file instead
#   --path DIR             CORTEX_SMOKE_PATH     tree to package and upload
#   --project NAME         CORTEX_PROJECT        history key on the server
#   --timeout SECONDS      CORTEX_TIMEOUT        wait for the verdict (default 900)
#   --poll-interval SECS   CORTEX_POLL_INTERVAL  between status checks (default 5)
#   --expect-pass          CORTEX_EXPECT_PASS=1  invert the gate expectation
#   --insecure             CORTEX_INSECURE=1     accept a self-signed certificate
#
# There is deliberately no --api-key flag. A flag value is visible in the
# process list to every other user on the host, which is why the key is read
# from the environment or from a file and reaches curl through a config file on
# stdin — never argv, never a query string, never the output. `cortex serve`
# refuses "?api_key=" for the same reason (see httpapi/auth.go).
#
# Exit: 0 every assertion held, 1 one did not, 2 bad usage or a missing tool.

set -euo pipefail

BASE_URL="${CORTEX_URL:-}"
API_KEY_ENV="CORTEX_API_KEY"
API_KEY_FILE="${CORTEX_API_KEY_FILE:-}"
PROJECT="${CORTEX_PROJECT:-cortex-smoke}"
TIMEOUT="${CORTEX_TIMEOUT:-900}"
POLL_INTERVAL="${CORTEX_POLL_INTERVAL:-5}"
EXPECT_PASS="${CORTEX_EXPECT_PASS:-0}"
INSECURE="${CORTEX_INSECURE:-0}"

# The default target is the vulnerable-by-design fixture that ships beside this
# repository: nine Python, six JavaScript and three Java files carrying SQLi,
# command injection, XXE, eval(), path traversal and hardcoded secrets (its
# README tabulates them by CWE). It is read-only here — the script packages a
# copy and never writes into it.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_PATH="$SCRIPT_DIR/../../kassandra-sast-demo-master"
SOURCE_PATH="${CORTEX_SMOKE_PATH:-$DEFAULT_PATH}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)            BASE_URL="$2"; shift 2 ;;
    --api-key-env)    API_KEY_ENV="$2"; shift 2 ;;
    --api-key-file)   API_KEY_FILE="$2"; shift 2 ;;
    --path)           SOURCE_PATH="$2"; shift 2 ;;
    --project)        PROJECT="$2"; shift 2 ;;
    --timeout)        TIMEOUT="$2"; shift 2 ;;
    --poll-interval)  POLL_INTERVAL="$2"; shift 2 ;;
    --expect-pass)    EXPECT_PASS=1; shift ;;
    --insecure)       INSECURE=1; shift ;;
    --api-key)
      echo "there is no --api-key: the value would be visible in the process" >&2
      echo "list. Export $API_KEY_ENV, or use --api-key-file." >&2
      exit 2 ;;
    -h|--help)        sed -n '2,38p' "$0"; exit 0 ;;
    *)                echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------

# curl and jq only, by design: this has to run on a client's CI runner, and
# anything else we ask for is a reason for it not to be run at all.
for tool in curl jq; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "$tool is required and not on PATH" >&2; exit 2; }
done

[[ -n "$BASE_URL" ]] || {
  echo "no server URL: pass --url or set CORTEX_URL" >&2; exit 2; }
BASE_URL="${BASE_URL%/}"

if [[ -n "$API_KEY_FILE" ]]; then
  [[ -r "$API_KEY_FILE" ]] || {
    echo "cannot read the API key file: $API_KEY_FILE" >&2; exit 2; }
  # Trailing newlines are what a key file usually has and what the header must
  # not: "Bearer abc\n" is a different credential to the server.
  API_KEY="$(tr -d '\r\n' < "$API_KEY_FILE")"
else
  API_KEY="${!API_KEY_ENV-}"
fi

[[ -n "${API_KEY:-}" ]] || {
  echo "no API key: export $API_KEY_ENV, or pass --api-key-file PATH." >&2
  echo "It is read from the environment on purpose — a key given as a flag" >&2
  echo "is readable by anyone who can run ps on this host." >&2
  exit 2; }

[[ -d "$SOURCE_PATH" ]] || {
  echo "not a directory: $SOURCE_PATH" >&2; exit 2; }
SOURCE_PATH="$(cd "$SOURCE_PATH" && pwd)"

# curl's config-file parser treats a quoted value as C-ish: backslash and
# double quote have to survive it, or a key containing either authenticates as
# something else. Escaped once here rather than at every call site.
API_KEY_ESCAPED="${API_KEY//\\/\\\\}"
API_KEY_ESCAPED="${API_KEY_ESCAPED//\"/\\\"}"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cortex-smoke.XXXXXX")"
# The archive is the client's source and the bodies may quote it back. Remove
# them whatever happens, including on the assertion failures below, which are
# the exits most likely to be taken.
trap 'rm -rf "$WORK_DIR"' EXIT
ARCHIVE="$WORK_DIR/source.zip"
BODY="$WORK_DIR/body.json"
SARIF="$WORK_DIR/analysis.sarif"

CURL_OPTS=(--silent --show-error --connect-timeout 10 --max-time 600)
[[ "$INSECURE" == "1" ]] && CURL_OPTS+=(--insecure)

# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

# request METHOD PATH OUTFILE [extra curl args…] → prints the status code.
#
# The credential goes in through `--config -`: a header written on stdin is
# never in this process's argv, so `ps` on the CI runner does not hand the key
# to whoever is logged in. Passing it as -H "Authorization: …" — which is what
# the GitHub action does — would.
request() {
  local method="$1" path="$2" out="$3"
  shift 3
  printf 'header = "Authorization: Bearer %s"\n' "$API_KEY_ESCAPED" \
    | curl "${CURL_OPTS[@]}" --config - \
        -o "$out" -w '%{http_code}' -X "$method" "$@" "$BASE_URL$path"
}

# anon_request is the same call with no credential at all, for the one check
# that has to be made without one.
anon_request() {
  local method="$1" path="$2" out="$3"
  shift 3
  curl "${CURL_OPTS[@]}" -o "$out" -w '%{http_code}' -X "$method" "$@" "$BASE_URL$path"
}

# server_said renders whatever came back, error field first. A non-2xx whose
# body is never shown turns every failure into "HTTP 400" and a guess.
server_said() {
  jq -r '.error // .message // .' < "$1" 2>/dev/null || head -c 2000 "$1"
}

fail() {
  echo >&2
  echo "SMOKE TEST FAILED: $*" >&2
  exit 1
}

expect_status() {
  local want="$1" got="$2" what="$3" body="$4"
  [[ "$got" == "$want" ]] && return 0
  echo >&2
  echo "$what returned HTTP $got, expected $want. The server said:" >&2
  server_said "$body" | sed 's/^/    /' >&2
  exit 1
}

echo "cortex smoke test → $BASE_URL"
echo

# ---------------------------------------------------------------------------
# 1. Liveness
# ---------------------------------------------------------------------------

if ! code="$(anon_request GET /healthz "$BODY")"; then
  fail "could not reach $BASE_URL/healthz at all — wrong URL, or nothing listening"
fi
expect_status 200 "$code" "GET /healthz" "$BODY"
echo "  healthz         200 $(jq -rc '.' < "$BODY" 2>/dev/null || echo '')"

# ---------------------------------------------------------------------------
# 2. The server is closed
# ---------------------------------------------------------------------------
#
# Before anything else is worth measuring: an unauthenticated upload must be
# refused. If it is not, the server will happily analyse — and store the source
# of — anything anyone posts at it, and no other result in this run matters.
# Checked against the upload endpoint specifically, because that is the one
# that takes a client's code.

if ! code="$(anon_request POST /api/v1/analyses/upload "$BODY")"; then
  fail "the unauthenticated probe did not complete; cannot prove the server is closed"
fi

if [[ "$code" =~ ^2 ]]; then
  echo >&2
  echo "════════════════════════════════════════════════════════════════" >&2
  echo " STOP. An unauthenticated POST to /api/v1/analyses/upload"        >&2
  echo " returned HTTP $code. This server accepts uploads from anyone."   >&2
  echo ""                                                                 >&2
  echo " Take it off the network now. Check server.api_keys, and check"   >&2
  echo " that nothing in front of it is stripping the Authorization"      >&2
  echo " header. Nothing else this script could report matters until"     >&2
  echo " that answer is 401."                                             >&2
  echo "════════════════════════════════════════════════════════════════" >&2
  exit 1
fi
expect_status 401 "$code" "unauthenticated POST /api/v1/analyses/upload" "$BODY"
echo "  auth            401 to an unauthenticated upload — as it should be"

# ---------------------------------------------------------------------------
# 3. Package the tree
# ---------------------------------------------------------------------------
#
# git archive is the right tool when there is a repository: it carries the
# tracked tree and no .git, so no history and no local credentials leave the
# machine. The fixture is not one — it ships unpacked, with no .git — so
# assuming git archive would fail at the point where the test looks healthy.
# `rev-parse --show-toplevel` rather than --is-inside-work-tree because the
# latter is true for any directory sitting *under* an unrelated checkout, and
# git archive would then package that parent instead.

toplevel="$(git -C "$SOURCE_PATH" rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -n "$toplevel" && "$toplevel" == "$SOURCE_PATH" ]]; then
  git -C "$SOURCE_PATH" archive --format=zip -o "$ARCHIVE" HEAD \
    || fail "git archive failed on $SOURCE_PATH"
  packaged_with="git archive HEAD"
else
  command -v zip >/dev/null 2>&1 \
    || fail "$SOURCE_PATH is not a git repository and zip is not installed"
  # Exclusions mirror what git archive would have left out anyway: vendored
  # dependencies and build output are not the client's code, and they are most
  # of the bytes the upload limit is there to bound.
  ( cd "$SOURCE_PATH" && zip --quiet --recurse-paths "$ARCHIVE" . \
      --exclude '.git/*' '*/.git/*' 'node_modules/*' '*/node_modules/*' \
                '*/__pycache__/*' '*.pyc' 'target/*' 'dist/*' 'build/*' ) \
    || fail "could not package $SOURCE_PATH with zip"
  packaged_with="zip (no git repository at that path)"
fi

[[ -s "$ARCHIVE" ]] || fail "the archive came out empty"
echo "  packaged        $(du -h "$ARCHIVE" | cut -f1) from $SOURCE_PATH via $packaged_with"

# ---------------------------------------------------------------------------
# 4. Upload
# ---------------------------------------------------------------------------

if ! code="$(request POST /api/v1/analyses/upload "$BODY" \
      -F "archive=@$ARCHIVE" \
      -F "project=$PROJECT" \
      -F "branch=smoke" \
      -F "commit=$(date -u +%Y%m%d%H%M%S)" \
      -F "repository=local/$(basename "$SOURCE_PATH")")"; then
  fail "the upload request did not complete"
fi
expect_status 202 "$code" "POST /api/v1/analyses/upload" "$BODY"

ANALYSIS_ID="$(jq -r '.id // empty' < "$BODY")"
[[ -n "$ANALYSIS_ID" ]] || fail "the server accepted the upload but returned no analysis id"
echo "  uploaded        202, analysis $ANALYSIS_ID"

# ---------------------------------------------------------------------------
# 5. Wait for a verdict
# ---------------------------------------------------------------------------

deadline=$(( $(date +%s) + TIMEOUT ))
status=""
printf '  analysing       '
while [[ "$(date +%s)" -lt "$deadline" ]]; do
  sleep "$POLL_INTERVAL"
  # A status check that fails is not the analysis failing: a proxy hiccup or a
  # restart mid-scan is normal, and the deadline is what decides in the end.
  if ! code="$(request GET "/api/v1/analyses/$ANALYSIS_ID" "$BODY")"; then
    printf '?'
    continue
  fi
  if [[ "$code" != "200" ]]; then
    printf '?'
    continue
  fi
  status="$(jq -r '.status // empty' < "$BODY")"
  if [[ "$status" == "completed" || "$status" == "failed" ]]; then
    break
  fi
  printf '.'
done
echo

if [[ "$status" != "completed" && "$status" != "failed" ]]; then
  fail "the analysis was still \"${status:-unknown}\" after ${TIMEOUT}s.
  Either the scan is slower than the timeout — raise --timeout — or a worker is
  wedged. On the server: cortex logs, and GET /api/v1/analyses?limit=5."
fi

if [[ "$status" == "failed" ]]; then
  fail "the analysis failed on the server: $(jq -r '.error // "no reason given"' < "$BODY")"
fi

# ---------------------------------------------------------------------------
# 6. The numbers
# ---------------------------------------------------------------------------

gate="$(jq -r '.gate // "unknown"' < "$BODY")"
findings="$(jq -r '.findings // 0' < "$BODY")"
new_findings="$(jq -r '.new_findings // 0' < "$BODY")"
scanners_ran="$(jq -r '.scanners_ran // 0' < "$BODY")"
scanner_errors="$(jq -r '(.scanner_errors // {}) | length' < "$BODY")"

# Positive evidence that the engine did something. Cortex treats a missing
# binary as a non-fatal per-scanner error, so an image built without the
# scanners answers 200, "completed", zero findings — indistinguishable from
# clean unless this number is read.
[[ "$scanners_ran" -gt 0 ]] || fail "scanners_ran is 0: the analysis completed without
  running a single scanner. The server has no scanner binaries on its PATH, or
  every one of them is disabled in its config."

if [[ "$EXPECT_PASS" != "1" && "$findings" -eq 0 ]]; then
  fail "0 findings on a repository that is vulnerable on purpose.
  $SOURCE_PATH carries SQL injection, command injection, XXE, eval() and
  hardcoded secrets. Zero means the scanners did not see the code — check that
  the archive was expanded, and that the languages in it were detected."
fi

# Reported whatever the verdict, and reported even when the gate agrees with
# us: a run where most tools failed must not read as a clean one.
if [[ "$scanner_errors" -gt 0 ]]; then
  echo "  WARNING: $scanner_errors scanner(s) did not complete. Every count below is a"
  echo "           floor, not a total:"
  jq -r '(.scanner_errors // {}) | to_entries[] | "             \(.key): \(.value)"' < "$BODY"
fi

if [[ "$EXPECT_PASS" == "1" ]]; then
  [[ "$gate" == "passed" ]] || fail "expected the gate to pass, and it is \"$gate\" ($findings findings).
  Run without --expect-pass if this target is not meant to be clean."
  echo "  gate            passed, as --expect-pass required"
else
  [[ "$gate" == "failed" ]] || fail "the gate says \"$gate\" on a deliberately vulnerable
  repository with $findings finding(s). Either the Quality Gate policy is too
  loose to stop anything — check the thresholds in the server's config — or the
  verdict is not being applied. A gate that never fails does not gate."
  echo "  gate            failed on the vulnerable fixture — the gate works"
fi

# ---------------------------------------------------------------------------
# 7. SARIF
# ---------------------------------------------------------------------------
#
# The document is the deliverable: it is what a client's Code Scanning tab and
# every downstream tool consume. A record that counts findings but cannot hand
# them over is not a working analysis.

if ! code="$(request GET "/api/v1/analyses/$ANALYSIS_ID/sarif" "$SARIF")"; then
  fail "the SARIF request did not complete"
fi
expect_status 200 "$code" "GET /api/v1/analyses/$ANALYSIS_ID/sarif" "$SARIF"

jq -e . < "$SARIF" >/dev/null 2>&1 || fail "the SARIF response is not valid JSON"

sarif_version="$(jq -r '.version // "missing"' < "$SARIF")"
[[ "$sarif_version" == "2.1.0" ]] \
  || fail "SARIF version is \"$sarif_version\", expected 2.1.0"

runs="$(jq -r '(.runs // []) | length' < "$SARIF")"
[[ "$runs" -gt 0 ]] || fail "the SARIF document has an empty runs array"

results="$(jq -r '[(.runs // [])[] | (.results // [])[]] | length' < "$SARIF")"
if [[ "$EXPECT_PASS" != "1" && "$results" -eq 0 ]]; then
  fail "the analysis reported $findings finding(s) but the SARIF carries none.
  The record and the document disagree — the findings are not being serialised."
fi
echo "  sarif           2.1.0, $runs run(s), $results result(s)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

severities="$(jq -r '
  (.by_severity // {}) as $s
  | ["critical","high","medium","low","info"]
  | map("\(.)=\($s[.] // 0)")
  | join("  ")' < "$BODY")"

# Only counts and names here. The key is not printed, and neither is anything
# that was sent with it.
cat <<EOF

───────────────────────────────────────────────
  analysis      $ANALYSIS_ID
  project       $PROJECT
  gate          $gate
  findings      $findings  ($new_findings new to this project)
  by severity   $severities
  scanners ran  $scanners_ran
  scanners bad  $scanner_errors
  sarif         $results result(s) in $runs run(s)
───────────────────────────────────────────────

Smoke test passed: the server accepted an upload, refused one without a key,
analysed it, and returned a verdict this script could check.
EOF
