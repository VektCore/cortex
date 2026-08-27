//go:build integration

// Integration tests: real scanners, real subprocesses, a real HTTP server —
// but no external network and no dependency on a deployed platform.
//
//	make test-integration
//
// The suite skips itself when no scanner is installed, so it stays runnable on
// a machine that only has Go.
package integration_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/interfaces/cli"
)

// fakePlatform is the server side of the remote state backend: the two calls a
// managed service has to answer for Cortex to keep a project's history.
type fakePlatform struct {
	mu       sync.Mutex
	state    map[string][]byte // project → stored document
	gets     int
	puts     int
	putCount int // vulnerabilities in the last PUT
}

func newFakePlatform() *fakePlatform {
	return &fakePlatform{state: make(map[string][]byte)}
}

func (p *fakePlatform) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		project := projectFromPath(r.URL.Path)
		if project == "" {
			http.NotFound(w, r)
			return
		}

		p.mu.Lock()
		defer p.mu.Unlock()

		switch r.Method {
		case http.MethodGet:
			p.gets++
			stored, ok := p.state[project]
			if !ok {
				// No history yet. Cortex must read this as a first scan.
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write(stored)

		case http.MethodPut:
			p.puts++
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var doc struct {
				Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
			}
			if unmarshalErr := json.Unmarshal(body, &doc); unmarshalErr != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			p.state[project] = body
			p.putCount = len(doc.Vulnerabilities)
			w.WriteHeader(http.StatusOK)

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

func (p *fakePlatform) snapshot() (gets, puts, count int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.gets, p.puts, p.putCount
}

// projectFromPath extracts "acme" from /api/v1/projects/acme/vulnerabilities.
func projectFromPath(path string) string {
	const prefix = "/api/v1/projects/"
	const suffix = "/vulnerabilities"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
}

func anyScannerInstalled() bool {
	for _, bin := range []string{"semgrep", "bandit", "gitleaks", "gosec"} {
		if _, err := exec.LookPath(bin); err == nil {
			return true
		}
	}
	return false
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "go.mod not found above %s", dir)
		dir = parent
	}
}

// This is the flow a managed service depends on: the history lives on the
// server, so a repository Cortex does not own still gets "3 new since last
// week" instead of the same 400 findings every run.
func TestRemoteState_HistoryLivesOnTheServer(t *testing.T) {
	if !anyScannerInstalled() {
		t.Skip("no scanner on PATH")
	}

	platform := newFakePlatform()
	srv := httptest.NewServer(platform.handler())
	defer srv.Close()

	root := repoRoot(t)
	fixture := filepath.Join(root, "test", "fixtures", "kassandra-sast-demo")
	work := t.TempDir()

	cfgPath := filepath.Join(work, "cortex.yaml")
	cfg := `version: "1"
scanners:
  semgrep:
    enabled: true
    options:
      config: "p/security-audit"
  bandit:   { enabled: true }
  gitleaks: { enabled: true }
  gosec:    { enabled: false }
  osv:      { enabled: false }
gate:
  rules: []
state:
  enabled: true
  backend: remote
  remote:
    url: ` + srv.URL + `
    token: integration-token
    project: fixture
publishers:
  filesystem:
    enabled: false
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfg), 0o600))

	args := []string{
		"scan", fixture, "-c", cfgPath,
		"--output", filepath.Join(work, "out"), "--quiet",
	}

	// First pass: the project has no history, so everything is new and the
	// state is written to the server rather than into the scanned repository.
	code := cli.Execute(context.Background(), args)
	require.Equal(t, cli.ExitOK, code, "an empty gate policy must not fail the run")

	gets, puts, stored := platform.snapshot()
	assert.Equal(t, 1, gets, "the first pass still asks the server for history")
	assert.Equal(t, 1, puts)
	require.Positive(t, stored, "the fixture is vulnerable on purpose, so state cannot be empty")

	assert.NoFileExists(t, filepath.Join(fixture, ".cortex", "state.json"),
		"the remote backend must not leave state inside the scanned repository")

	// Second pass over unchanged code: the server's history is read back, so
	// nothing is new. That is the whole point of keeping state centrally.
	code = cli.Execute(context.Background(), args)
	require.Equal(t, cli.ExitOK, code)

	gets, puts, storedAgain := platform.snapshot()
	assert.Equal(t, 2, gets)
	assert.Equal(t, 2, puts)
	assert.Equal(t, stored, storedAgain,
		"re-scanning unchanged code must not grow the tracked set")
}

// A platform that is down must not be reported as a clean scan.
func TestRemoteState_ServerFailureIsNotSilent(t *testing.T) {
	if !anyScannerInstalled() {
		t.Skip("no scanner on PATH")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"database unavailable"}`))
	}))
	defer srv.Close()

	root := repoRoot(t)
	work := t.TempDir()
	cfgPath := filepath.Join(work, "cortex.yaml")
	cfg := `version: "1"
scanners:
  semgrep:  { enabled: false }
  bandit:   { enabled: true }
  gitleaks: { enabled: false }
  gosec:    { enabled: false }
  osv:      { enabled: false }
gate:
  rules: []
state:
  enabled: true
  backend: remote
  remote:
    url: ` + srv.URL + `
    token: t
    project: fixture
publishers:
  filesystem:
    enabled: false
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfg), 0o600))

	code := cli.Execute(context.Background(), []string{
		"scan", filepath.Join(root, "test", "fixtures", "kassandra-sast-demo"),
		"-c", cfgPath, "--output", filepath.Join(work, "out"), "--quiet",
	})

	assert.Equal(t, cli.ExitScannerError, code,
		"a state backend that cannot be read is an infrastructure failure, not a pass")
}
