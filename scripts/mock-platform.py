#!/usr/bin/env python3
"""Reference implementation of the platform API Cortex talks to.

It exists for two reasons: to let anyone exercise the remote state backend
before the real platform is up, and to pin down — in code rather than prose —
the three endpoints the server has to provide.

    scripts/mock-platform.py [--port 8790] [--dir .mock-platform]

Then point Cortex at it:

    state:
      enabled: true
      backend: remote
      remote:
        url: http://127.0.0.1:8790
        token: dev-token
        project: my-project
    publishers:
      korvlabs:
        enabled: true
        url: http://127.0.0.1:8790
        api_key: dev-token

Endpoints
---------
POST /api/v1/scans
    Ingest. Body is the merged SARIF, Content-Type application/sarif+json.
    Responds 201 {"id": ..., "url": ...}. The real server associates the
    document with project, branch and commit.

GET  /api/v1/projects/<project>/vulnerabilities
    The project's vulnerability state. 404 (or an empty document) means the
    project has no history yet — Cortex treats that as a first scan, never as
    an error.

PUT  /api/v1/projects/<project>/vulnerabilities
    Replaces the state. The body is the whole document, so a retried CI job
    cannot duplicate anybody's triage.

Storage here is one JSON file per project. Not for production: no auth beyond
comparing a token, no concurrency control, no history.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VULN_PATH = re.compile(r"^/api/v1/projects/([A-Za-z0-9._\-]+)/vulnerabilities/?$")
SCANS_PATH = "/api/v1/scans"

STATE_DIR = ".mock-platform"
TOKEN = None  # any token accepted when None


def state_file(project: str) -> str:
    return os.path.join(STATE_DIR, f"{project}.state.json")


class Handler(BaseHTTPRequestHandler):
    server_version = "mock-platform/1.0"

    # ---------- helpers ----------

    def _json(self, status: int, payload) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        if TOKEN is None:
            return True
        return self.headers.get("Authorization") == f"Bearer {TOKEN}"

    def _read_body(self) -> bytes:
        return self.rfile.read(int(self.headers.get("Content-Length", 0)))

    def _deny(self) -> None:
        self._json(403, {"error": "invalid or missing project token"})

    # ---------- routes ----------

    def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler's naming
        match = VULN_PATH.match(self.path)
        if not match:
            self._json(404, {"error": f"no route for GET {self.path}"})
            return
        if not self._authorized():
            self._deny()
            return

        project = match.group(1)
        path = state_file(project)
        if not os.path.exists(path):
            # No history yet. Cortex reads this as an empty state.
            self._json(404, {"error": f"project {project} has no state yet"})
            return

        with open(path, "rb") as fh:
            body = fh.read()
        count = len(json.loads(body).get("vulnerabilities", []))
        print(f"GET  state   project={project} vulnerabilities={count}", flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):  # noqa: N802
        match = VULN_PATH.match(self.path)
        if not match:
            self._json(404, {"error": f"no route for PUT {self.path}"})
            return
        if not self._authorized():
            self._deny()
            return

        project = match.group(1)
        body = self._read_body()
        try:
            doc = json.loads(body)
        except json.JSONDecodeError as exc:
            self._json(400, {"error": f"body is not JSON: {exc}"})
            return

        os.makedirs(STATE_DIR, exist_ok=True)
        with open(state_file(project), "wb") as fh:
            fh.write(body)

        count = len(doc.get("vulnerabilities", []))
        print(f"PUT  state   project={project} vulnerabilities={count}", flush=True)
        self._json(200, {"project": project, "vulnerabilities": count})

    def do_POST(self):  # noqa: N802
        if self.path.rstrip("/") != SCANS_PATH:
            self._json(404, {"error": f"no route for POST {self.path}"})
            return
        if not self._authorized():
            self._deny()
            return

        body = self._read_body()
        scan_id = self.headers.get("X-Scan-ID") or datetime.now(timezone.utc).strftime(
            "%Y%m%d%H%M%S"
        )
        os.makedirs(os.path.join(STATE_DIR, "scans"), exist_ok=True)
        out = os.path.join(STATE_DIR, "scans", f"{scan_id}.sarif")
        with open(out, "wb") as fh:
            fh.write(body)

        results = 0
        try:
            doc = json.loads(body)
            results = sum(len(run.get("results", [])) for run in doc.get("runs", []))
        except json.JSONDecodeError:
            pass

        print(
            f"POST scan    id={scan_id} results={results} "
            f"bytes={len(body)} → {out}",
            flush=True,
        )
        self._json(201, {"id": scan_id, "url": f"http://{self.headers.get('Host')}/scans/{scan_id}"})

    def log_message(self, *args):
        pass  # the routes print what matters


def main() -> int:
    global STATE_DIR, TOKEN

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8790)
    parser.add_argument("--dir", default=STATE_DIR, help="where to keep state and scans")
    parser.add_argument("--token", default=None, help="require this bearer token")
    args = parser.parse_args()

    STATE_DIR = args.dir
    TOKEN = args.token
    os.makedirs(STATE_DIR, exist_ok=True)

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(
        f"mock platform on http://127.0.0.1:{args.port}  "
        f"state in {STATE_DIR}/  "
        f"token={'any' if TOKEN is None else 'required'}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
