package httpapi_test

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/infrastructure/config"
	"github.com/vektcore/cortex/internal/infrastructure/logging"
	"github.com/vektcore/cortex/internal/interfaces/httpapi"
)

// Two clients, two keys, and nothing of one visible to the other.
//
// Every test here fails against the version of this server that had per-client
// keys and no authorisation: the key said who you were, and then every handler
// served every client's records regardless. These are the assertions that
// would have caught it.

const (
	aliceKey = "sk-alice-key"
	bobKey   = "sk-bob-key"
)

// newTenantServer runs one server that two clients share, which is the whole
// point: isolation that only holds because each client got its own process is
// not isolation.
func newTenantServer(t *testing.T) (http.Handler, string) {
	t.Helper()

	dataDir := t.TempDir()
	cfg := &config.Config{}
	cfg.Server.DataDir = dataDir
	cfg.Server.Workers = 1
	cfg.Server.APIKeys = []config.APIKey{
		{Name: "alice", Key: aliceKey},
		{Name: "bob", Key: bobKey},
	}
	cfg.Server.Upload.Enabled = true
	cfg.Server.Upload.MaxArchiveBytes = 1 << 20
	cfg.Server.Upload.MaxExtractedBytes = 4 << 20
	cfg.Server.Upload.MaxEntries = 100
	cfg.State.Enabled = true

	srv, err := httpapi.New(cfg, logging.NewNop())
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	return srv.Handler(), dataDir
}

// queueFor submits a git analysis as one client and returns the queued record.
func queueFor(t *testing.T, h http.Handler, key, project string) httpapi.Analysis {
	t.Helper()

	rec := do(t, h, http.MethodPost, "/api/v1/analyses",
		`{"repository":"github.com/org/`+project+`","project":"`+project+`"}`, key)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())

	var a httpapi.Analysis
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &a))
	return a
}

func listFor(t *testing.T, h http.Handler, key, query string) []httpapi.Analysis {
	t.Helper()

	rec := do(t, h, http.MethodGet, "/api/v1/analyses"+query, "", key)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var page struct {
		Analyses []httpapi.Analysis `json:"analyses"`
		Count    int                `json:"count"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	require.Equal(t, len(page.Analyses), page.Count)
	return page.Analyses
}

// GET /api/v1/analyses used to be a directory of every client on the server.
func TestTenancy_ListingShowsOnlyTheCallersOwnAnalyses(t *testing.T) {
	t.Parallel()
	h, _ := newTenantServer(t)

	mine := queueFor(t, h, aliceKey, "alice-api")
	theirs := queueFor(t, h, bobKey, "bob-api")

	forAlice := listFor(t, h, aliceKey, "")
	require.Len(t, forAlice, 1)
	assert.Equal(t, mine.ID, forAlice[0].ID)

	forBob := listFor(t, h, bobKey, "")
	require.Len(t, forBob, 1)
	assert.Equal(t, theirs.ID, forBob[0].ID)
}

// ?project= is the caller's own name, resolved inside the caller's namespace.
// Naming the other client's project must not reach across.
func TestTenancy_ProjectFilterCannotReachAnotherClient(t *testing.T) {
	t.Parallel()
	h, _ := newTenantServer(t)

	queueFor(t, h, aliceKey, "shared")

	assert.Empty(t, listFor(t, h, bobKey, "?project=shared"),
		"bob naming alice's project must not list alice's analyses")
	assert.Len(t, listFor(t, h, aliceKey, "?project=shared"), 1)
}

// The id is the whole credential for reading a record, and ids are guessable
// enough to be worth enumerating. A 403 would confirm which ones exist.
func TestTenancy_AnotherClientsAnalysisIsNotFoundNotForbidden(t *testing.T) {
	t.Parallel()
	h, _ := newTenantServer(t)

	theirs := queueFor(t, h, aliceKey, "alice-api")

	got := do(t, h, http.MethodGet, "/api/v1/analyses/"+theirs.ID, "", bobKey)
	assert.Equal(t, http.StatusNotFound, got.Code)
	assert.NotContains(t, got.Body.String(), "alice",
		"the 404 must not leak the owner it refused to serve")

	unknown := do(t, h, http.MethodGet, "/api/v1/analyses/doesnotexist", "", bobKey)
	assert.Equal(t, unknown.Code, got.Code,
		"an id that exists and an id that does not must be indistinguishable")
}

// The SARIF is the sensitive half: it carries the client's file paths and the
// source lines around each finding.
func TestTenancy_AnotherClientsSARIFIsNotReadable(t *testing.T) {
	t.Parallel()
	h, _ := newTenantServer(t)

	rec := postUpload(t, h,
		map[string]string{"project": "alice-api", "commit": "deadbeefdeadbeef"},
		sampleArchive(t), aliceKey)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())

	var queued httpapi.Analysis
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &queued))
	final := waitForTerminal(t, h, queued.ID, aliceKey)
	require.Equal(t, httpapi.StatusCompleted, final.Status, final.Error)

	sarifPath := "/api/v1/analyses/" + queued.ID + "/sarif"
	mine := do(t, h, http.MethodGet, sarifPath, "", aliceKey)
	require.Equal(t, http.StatusOK, mine.Code, "the owner still reads its own")

	theirs := do(t, h, http.MethodGet, sarifPath, "", bobKey)
	assert.Equal(t, http.StatusNotFound, theirs.Code)
	assert.NotContains(t, theirs.Body.String(), "version",
		"not one byte of the document may come back")
}

// Reading another client's finding history tells you what they are shipping
// with. Writing it rewrites what their next quality gate calls "new", which
// turns a blocking gate into a passing one.
func TestTenancy_ProjectStateIsPerClientForTheSameName(t *testing.T) {
	t.Parallel()
	h, _ := newTenantServer(t)

	const path = "/api/v1/projects/shared/vulnerabilities"
	aliceDoc := `{"version":1,"vulnerabilities":[{"exact":"alice-1"},{"exact":"alice-2"}]}`
	bobDoc := `{"version":1,"vulnerabilities":[]}`

	require.Equal(t, http.StatusOK,
		do(t, h, http.MethodPut, path, aliceDoc, aliceKey).Code)

	// Bob asks for the same project name and gets a first scan, not alice's
	// history.
	unseen := do(t, h, http.MethodGet, path, "", bobKey)
	assert.Equal(t, http.StatusNotFound, unseen.Code)
	assert.NotContains(t, unseen.Body.String(), "alice-1")

	// And bob writing it does not overwrite alice's.
	require.Equal(t, http.StatusOK,
		do(t, h, http.MethodPut, path, bobDoc, bobKey).Code)

	back := do(t, h, http.MethodGet, path, "", aliceKey)
	require.Equal(t, http.StatusOK, back.Code)
	assert.JSONEq(t, aliceDoc, back.Body.String(),
		"another client's PUT must not have replaced this client's history")

	bobBack := do(t, h, http.MethodGet, path, "", bobKey)
	require.Equal(t, http.StatusOK, bobBack.Code)
	assert.JSONEq(t, bobDoc, bobBack.Body.String())
}

// X-Scan-ID is caller-supplied, so a global id space let anyone replace
// anyone's ingested document by naming their id.
func TestTenancy_IngestingUnderAnotherClientsScanIDDoesNotOverwriteIt(t *testing.T) {
	t.Parallel()
	h, dataDir := newTenantServer(t)

	const id = "shared-scan-id"
	aliceSARIF := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"alice"}}}]}`
	bobSARIF := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"bob"}}}]}`

	require.Equal(t, http.StatusCreated, ingest(t, h, aliceKey, id, aliceSARIF).Code)
	require.Equal(t, http.StatusCreated, ingest(t, h, bobKey, id, bobSARIF).Code)

	stored := storedScans(t, filepath.Join(dataDir, "scans"))
	require.Len(t, stored, 2,
		"one id posted by two clients is two documents, not one overwritten")
	assert.Contains(t, stored, aliceSARIF)
	assert.Contains(t, stored, bobSARIF)
}

// Uploading under a name another client already uses used to reconcile these
// findings into that client's history.
func TestTenancy_UploadUnderACollidingProjectNameStaysInItsOwnNamespace(t *testing.T) {
	t.Parallel()
	h, _ := newTenantServer(t)

	const statePath = "/api/v1/projects/shared/vulnerabilities"
	aliceDoc := `{"version":1,"vulnerabilities":[{"exact":"alice-only"}]}`
	require.Equal(t, http.StatusOK,
		do(t, h, http.MethodPut, statePath, aliceDoc, aliceKey).Code)

	rec := postUpload(t, h,
		map[string]string{"project": "shared", "commit": "cafebabecafebabe"},
		sampleArchive(t), bobKey)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())

	var queued httpapi.Analysis
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &queued))
	assert.Equal(t, "bob/shared", queued.Project,
		"the same name asked for by two clients is two projects")

	final := waitForTerminal(t, h, queued.ID, bobKey)
	require.Equal(t, httpapi.StatusCompleted, final.Status, final.Error)

	back := do(t, h, http.MethodGet, statePath, "", aliceKey)
	require.Equal(t, http.StatusOK, back.Code)
	assert.JSONEq(t, aliceDoc, back.Body.String(),
		"bob's run reconciled into bob's history, not into alice's")

	assert.Empty(t, listFor(t, h, aliceKey, "?project=shared"),
		"and bob's analysis is not alice's to see")
}

// A webhook delivery has no API client, so it goes to a reserved owner. No key
// authenticates as that owner, so no client sees those runs.
func TestTenancy_WebhookAnalysesBelongToNoClient(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	cfg.Server.DataDir = t.TempDir()
	cfg.Server.Workers = 1
	cfg.Server.APIKeys = []config.APIKey{{Name: "alice", Key: aliceKey}}
	cfg.Server.WebhookSecret = webhookSecret

	srv, err := httpapi.New(cfg, logging.NewNop())
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	h := srv.Handler()

	body := pushBody("master", "someone/private-repo", false)
	rec := deliver(t, h, "push", body, sign(webhookSecret, body))
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())

	var queued map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &queued))

	assert.Empty(t, listFor(t, h, aliceKey, ""),
		"a client must not inherit runs it did not request")
	assert.Equal(t, http.StatusNotFound,
		do(t, h, http.MethodGet, "/api/v1/analyses/"+queued["id"], "", aliceKey).Code)
}

// The reserved prefix is what keeps the webhook's namespace out of reach. A
// key issued with such a name is refused rather than handed that namespace.
func TestTenancy_AClientNamedLikeAReservedOwnerIsRefused(t *testing.T) {
	t.Parallel()

	const impostorKey = "sk-impostor"
	cfg := &config.Config{}
	cfg.Server.DataDir = t.TempDir()
	cfg.Server.Workers = 1
	cfg.Server.APIKeys = []config.APIKey{
		{Name: "cortex:github-webhook", Key: impostorKey},
	}

	srv, err := httpapi.New(cfg, logging.NewNop())
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	rec := do(t, srv.Handler(), http.MethodGet, "/api/v1/analyses", "", impostorKey)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "reserved")
}

// Operator access is opt-in and comes from the server's own environment. Not
// parallel: it sets one.
func TestTenancy_OperatorAccessIsExplicitAndOffByDefault(t *testing.T) {
	const operatorKey = "sk-operator"

	build := func(t *testing.T, admins ...string) http.Handler {
		t.Helper()
		cfg := &config.Config{}
		cfg.Server.DataDir = t.TempDir()
		cfg.Server.Workers = 1
		cfg.Server.APIKeys = []config.APIKey{
			{Name: "alice", Key: aliceKey},
			{Name: "operator", Key: operatorKey},
		}
		cfg.Server.AdminClients = admins
		srv, err := httpapi.New(cfg, logging.NewNop())
		require.NoError(t, err)
		t.Cleanup(srv.Close)
		return srv.Handler()
	}

	t.Run("off by default", func(t *testing.T) {
		// Nothing named: the default, and the point of the subtest.
		h := build(t)
		theirs := queueFor(t, h, aliceKey, "alice-api")

		assert.Empty(t, listFor(t, h, operatorKey, ""),
			"a key is never enough; the operator has to say so out of band")
		assert.Equal(t, http.StatusNotFound,
			do(t, h, http.MethodGet, "/api/v1/analyses/"+theirs.ID, "", operatorKey).Code)
	})

	t.Run("on when the operator names the client", func(t *testing.T) {
		h := build(t, "operator")
		theirs := queueFor(t, h, aliceKey, "alice-api")

		seen := listFor(t, h, operatorKey, "")
		require.Len(t, seen, 1)
		assert.Equal(t, theirs.ID, seen[0].ID)
		assert.Equal(t, http.StatusOK,
			do(t, h, http.MethodGet, "/api/v1/analyses/"+theirs.ID, "", operatorKey).Code)

		// ?owner= narrows to one tenant; a tenant nobody owns is empty rather
		// than everything.
		assert.Len(t, listFor(t, h, operatorKey, "?owner=alice"), 1)
		assert.Empty(t, listFor(t, h, operatorKey, "?owner=nobody"))
	})

	t.Run("naming a client does not elevate the others", func(t *testing.T) {
		h := build(t, "operator")
		queueFor(t, h, operatorKey, "operator-api")

		assert.Empty(t, listFor(t, h, aliceKey, ""))
	})
}

// A 500 used to carry the wrapped error, which on the Postgres backend spells
// out the database host, user and database name. Nothing in an error body may
// describe the server's own storage.
func TestTenancy_ErrorsDoNotDescribeTheServersStorage(t *testing.T) {
	t.Parallel()
	h, dataDir := newTenantServer(t)

	// An oversized archive is the failure path that used to return an
	// *os.PathError naming the data directory.
	big, _ := newUploadServer(t, func(c *config.Config) {
		c.Server.Upload.MaxArchiveBytes = 64
	})
	over := postUpload(t, big, map[string]string{"project": "p"}, sampleArchive(t), testKey)
	assert.NotContains(t, over.Body.String(), os.TempDir())

	for _, path := range []string{
		"/api/v1/analyses",
		"/api/v1/analyses/nope",
		"/api/v1/projects/nope/vulnerabilities",
	} {
		body := do(t, h, http.MethodGet, path, "", aliceKey).Body.String()
		assert.NotContains(t, body, dataDir, path)
		assert.NotContains(t, body, "pgx", path)
	}
}

// ingest posts a SARIF document under a caller-chosen scan id, which is the
// shape of the overwrite this endpoint used to allow.
func ingest(
	t *testing.T, h http.Handler, key, id, doc string,
) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(doc))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Scan-ID", id)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// storedScans reads back every ingested document under root, so a test can
// assert on what actually landed without knowing the directory scheme.
func storedScans(t *testing.T, root string) []string {
	t.Helper()

	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".sarif") {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		out = append(out, string(raw))
		return nil
	})
	require.NoError(t, err)
	return out
}
