package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/infrastructure/config"
	"github.com/vektcore/cortex/internal/infrastructure/logging"
	"github.com/vektcore/cortex/internal/interfaces/httpapi"
)

const testKey = "sk-test-key"

func newTestServer(t *testing.T) http.Handler {
	t.Helper()

	cfg := &config.Config{}
	cfg.Server.DataDir = t.TempDir()
	cfg.Server.Workers = 1
	cfg.Server.APIKeys = []config.APIKey{{Name: "test-client", Key: testKey}}
	cfg.State.Enabled = true

	srv, err := httpapi.New(cfg, logging.NewNop())
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	return srv.Handler()
}

func do(t *testing.T, h http.Handler, method, path, body, key string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The server can clone arbitrary repositories, so starting one without
// credentials would hand that to anybody who can reach the port.
func TestNew_RefusesToStartWithoutAPIKeys(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	cfg.Server.DataDir = t.TempDir()

	_, err := httpapi.New(cfg, logging.NewNop())

	require.Error(t, err)
	assert.ErrorIs(t, err, httpapi.ErrNoAPIKeys)
}

func TestHealth_NeedsNoCredentials(t *testing.T) {
	t.Parallel()
	h := newTestServer(t)

	rec := do(t, h, http.MethodGet, "/healthz", "", "")

	assert.Equal(t, http.StatusOK, rec.Code,
		"a load balancer cannot be expected to hold an API key")
}

func TestAuth_RejectsMissingAndWrongKeys(t *testing.T) {
	t.Parallel()
	h := newTestServer(t)

	for name, key := range map[string]string{
		"no key":                "",
		"wrong key":             "sk-not-it",
		"prefix of a valid key": testKey[:len(testKey)-1],
	} {
		t.Run(name, func(t *testing.T) {
			rec := do(t, h, http.MethodGet, "/api/v1/analyses", "", key)
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.NotContains(t, rec.Body.String(), testKey,
				"an error must never echo a credential back")
		})
	}
}

func TestCreateAnalysis_ValidatesTheTarget(t *testing.T) {
	t.Parallel()
	h := newTestServer(t)

	tests := map[string]struct {
		body string
		want int
		msg  string
	}{
		"empty body":     {`{}`, http.StatusBadRequest, "required"},
		"not JSON":       {`nope`, http.StatusBadRequest, "JSON"},
		"a local path":   {`{"repository":"/etc"}`, http.StatusBadRequest, "git URL"},
		"a relative dir": {`{"repository":"../.."}`, http.StatusBadRequest, "git URL"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rec := do(t, h, http.MethodPost, "/api/v1/analyses", tc.body, testKey)
			assert.Equal(t, tc.want, rec.Code)
			assert.Contains(t, rec.Body.String(), tc.msg)
		})
	}
}

// A path is not a repository: scanning the server's own disk is not the
// caller's to ask for.
func TestCreateAnalysis_AcceptsAGitURLAndQueuesIt(t *testing.T) {
	t.Parallel()
	h := newTestServer(t)

	rec := do(t, h, http.MethodPost, "/api/v1/analyses",
		`{"repository":"github.com/org/repo","project":"acme"}`, testKey)

	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())

	var a httpapi.Analysis
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &a))
	assert.NotEmpty(t, a.ID)
	assert.Equal(t, "acme", a.Project)
	assert.Equal(t, httpapi.StatusQueued, a.Status)
	assert.Equal(t, "test-client", a.RequestedBy,
		"work is attributed to the named client, never to a raw key")
	assert.Equal(t, "/api/v1/analyses/"+a.ID, rec.Header().Get("Location"))
}

// Omitting the project must not silently start a fresh history every run.
func TestCreateAnalysis_DerivesAStableProject(t *testing.T) {
	t.Parallel()
	h := newTestServer(t)

	first := do(t, h, http.MethodPost, "/api/v1/analyses",
		`{"repository":"github.com/org/repo"}`, testKey)
	second := do(t, h, http.MethodPost, "/api/v1/analyses",
		`{"repository":"https://github.com/org/repo.git"}`, testKey)

	var a, b httpapi.Analysis
	require.NoError(t, json.Unmarshal(first.Body.Bytes(), &a))
	require.NoError(t, json.Unmarshal(second.Body.Bytes(), &b))

	assert.Equal(t, "org-repo", a.Project)
	assert.Equal(t, a.Project, b.Project,
		"the same repository in two URL forms is one project, not two")
}

func TestGetAnalysis_UnknownIDIsNotFound(t *testing.T) {
	t.Parallel()
	h := newTestServer(t)

	rec := do(t, h, http.MethodGet, "/api/v1/analyses/deadbeef", "", testKey)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// The state endpoints are the server side of the remote backend.
func TestProjectState_RoundTrip(t *testing.T) {
	t.Parallel()
	h := newTestServer(t)

	const path = "/api/v1/projects/acme/vulnerabilities"

	missing := do(t, h, http.MethodGet, path, "", testKey)
	assert.Equal(t, http.StatusNotFound, missing.Code,
		"a project with no history yet reads as a first scan, not an error")

	doc := `{"version":1,"vulnerabilities":[{"exact":"abc"},{"exact":"def"}]}`
	put := do(t, h, http.MethodPut, path, doc, testKey)
	require.Equal(t, http.StatusOK, put.Code, put.Body.String())
	assert.Contains(t, put.Body.String(), `"vulnerabilities": 2`)

	get := do(t, h, http.MethodGet, path, "", testKey)
	require.Equal(t, http.StatusOK, get.Code)
	assert.JSONEq(t, doc, get.Body.String(),
		"what the server returns must be exactly what the client stored")
}

func TestProjectState_RejectsSomethingThatIsNotAState(t *testing.T) {
	t.Parallel()
	h := newTestServer(t)

	rec := do(t, h, http.MethodPut, "/api/v1/projects/acme/vulnerabilities",
		`not json at all`, testKey)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// A project name is used to build a path, so it must not be able to escape the
// data directory.
func TestProjectState_PathTraversalIsNeutralised(t *testing.T) {
	t.Parallel()
	h := newTestServer(t)

	rec := do(t, h, http.MethodPut,
		"/api/v1/projects/..%2f..%2fetc/vulnerabilities",
		`{"version":1,"vulnerabilities":[]}`, testKey)

	// Either it is rejected or it is written under a sanitised name; what must
	// never happen is a write outside the data directory.
	assert.NotEqual(t, http.StatusInternalServerError, rec.Code)
	assert.NoFileExists(t, "/etc/vulnerabilities")
}

func TestIngestScan_StoresTheDocument(t *testing.T) {
	t.Parallel()
	h := newTestServer(t)

	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[]}]}`
	rec := do(t, h, http.MethodPost, "/api/v1/scans", sarif, testKey)

	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var got map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.NotEmpty(t, got["id"])
}

func TestIngestScan_EmptyBodyIsRejected(t *testing.T) {
	t.Parallel()
	h := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer "+testKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestMethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := newTestServer(t)

	rec := do(t, h, http.MethodDelete, "/api/v1/analyses", "", testKey)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}
