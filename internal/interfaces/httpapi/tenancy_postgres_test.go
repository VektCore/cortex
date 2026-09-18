//go:build integration

package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/infrastructure/apikeys"
	"github.com/vektcore/cortex/internal/infrastructure/config"
	"github.com/vektcore/cortex/internal/infrastructure/logging"
	"github.com/vektcore/cortex/internal/interfaces/httpapi"
)

// The same isolation, against a real database.
//
// It is asserted twice on purpose. The file backend filters in Go and the
// Postgres one filters in SQL, so they are two separate implementations of one
// rule, and a fix applied to only one of them is the likeliest way for this
// bug to come back.

// twoTenantsOnPostgres issues a real key per client into the database and
// returns the shared handler with both secrets.
func twoTenantsOnPostgres(t *testing.T) (http.Handler, string, string) {
	t.Helper()

	dsn := os.Getenv("CORTEX_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set CORTEX_TEST_POSTGRES_DSN to run the postgres tenancy tests")
	}

	dir := t.TempDir()
	keys, err := apikeys.Open(context.Background(), dsn, dir)
	require.NoError(t, err)

	// Distinct client names per run: the database outlives the test, and two
	// runs sharing an owner would make each other's rows visible and turn a
	// real regression into a flake.
	stamp := time.Now().UTC().Format("150405.000000")
	_, aliceSecret, err := keys.Issue(context.Background(), "alice-"+stamp, 90*day, time.Now())
	require.NoError(t, err)
	_, bobSecret, err := keys.Issue(context.Background(), "bob-"+stamp, 90*day, time.Now())
	require.NoError(t, err)
	keys.Close()

	cfg := &config.Config{}
	cfg.Server.DataDir = dir
	cfg.Server.Database = dsn
	cfg.Server.Workers = 1
	cfg.Server.Upload.Enabled = true
	cfg.Server.Upload.MaxArchiveBytes = 1 << 20
	cfg.Server.Upload.MaxExtractedBytes = 4 << 20
	cfg.Server.Upload.MaxEntries = 100
	cfg.State.Enabled = true

	srv, err := httpapi.New(cfg, logging.NewNop())
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	return srv.Handler(), aliceSecret, bobSecret
}

// The listing, the record and its SARIF, all out of one shared table.
func TestPostgresTenancy_OneClientIsBlindToTheOther(t *testing.T) {
	h, aliceKey, bobKey := twoTenantsOnPostgres(t)

	// Both clients call their project the same thing, which is the collision a
	// global project namespace merged into one history.
	rec := postUpload(t, h, map[string]string{
		"project": "shared",
		"commit":  "9f2a1c4e8b7d6a5f4e3c2b1a0987654321fedcba",
		"branch":  "main",
	}, sampleArchive(t), aliceKey)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())

	var hers httpapi.Analysis
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &hers))
	final := waitForTerminal(t, h, hers.ID, aliceKey)
	require.Equal(t, httpapi.StatusCompleted, final.Status, final.Error)

	assert.Empty(t, listFor(t, h, bobKey, ""),
		"a listing served from a shared table is still one tenant's listing")
	assert.Empty(t, listFor(t, h, bobKey, "?project=shared"),
		"naming her project is not a way into it")
	assert.Len(t, listFor(t, h, aliceKey, "?project=shared"), 1)

	assert.Equal(t, http.StatusNotFound,
		do(t, h, http.MethodGet, "/api/v1/analyses/"+hers.ID, "", bobKey).Code,
		"404, not 403: a 403 confirms the id exists")
	assert.Equal(t, http.StatusNotFound,
		do(t, h, http.MethodGet, "/api/v1/analyses/"+hers.ID+"/sarif", "", bobKey).Code)

	// And she still reads her own, so this is isolation rather than breakage.
	assert.Equal(t, http.StatusOK,
		do(t, h, http.MethodGet, "/api/v1/analyses/"+hers.ID+"/sarif", "", aliceKey).Code)
}

// Project state and ingested scans stay on disk whichever backend holds the
// records, so the scoping has to hold there too when Postgres is configured.
func TestPostgresTenancy_ProjectStateAndScansStayPerClient(t *testing.T) {
	h, aliceKey, bobKey := twoTenantsOnPostgres(t)

	const path = "/api/v1/projects/shared/vulnerabilities"
	aliceDoc := `{"version":1,"vulnerabilities":[{"exact":"alice-1"}]}`
	bobDoc := `{"version":1,"vulnerabilities":[]}`

	require.Equal(t, http.StatusOK, do(t, h, http.MethodPut, path, aliceDoc, aliceKey).Code)
	assert.Equal(t, http.StatusNotFound, do(t, h, http.MethodGet, path, "", bobKey).Code)

	require.Equal(t, http.StatusOK, do(t, h, http.MethodPut, path, bobDoc, bobKey).Code)
	back := do(t, h, http.MethodGet, path, "", aliceKey)
	require.Equal(t, http.StatusOK, back.Code)
	assert.JSONEq(t, aliceDoc, back.Body.String())

	const scanID = "shared-scan-id"
	require.Equal(t, http.StatusCreated,
		ingest(t, h, aliceKey, scanID, `{"version":"2.1.0","runs":[]}`).Code)
	require.Equal(t, http.StatusCreated,
		ingest(t, h, bobKey, scanID, `{"version":"2.1.0","runs":[{}]}`).Code)
}
