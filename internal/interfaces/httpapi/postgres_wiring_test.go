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

// serverOnPostgres builds the server the way a real deployment does: keys and
// analyses in the database, archives on disk.
func serverOnPostgres(t *testing.T) (http.Handler, string) {
	t.Helper()

	dsn := os.Getenv("CORTEX_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set CORTEX_TEST_POSTGRES_DSN to run the postgres wiring tests")
	}

	dir := t.TempDir()
	keys, err := apikeys.Open(context.Background(), dsn, dir)
	require.NoError(t, err)
	_, secret, err := keys.Issue(context.Background(), "wiring", 90*day, time.Now())
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

	return srv.Handler(), secret
}

// The whole path a client's pipeline takes, against a real database: a key
// issued into Postgres authenticates, the upload is queued, the worker records
// the analysis there, and both the record and its SARIF come back out.
func TestPostgresWiring_UploadIsStoredAndServedFromTheDatabase(t *testing.T) {
	h, secret := serverOnPostgres(t)

	project := "wiring-" + time.Now().UTC().Format("150405.000000")
	rec := postUpload(t, h, map[string]string{
		"project": project,
		"commit":  "9f2a1c4e8b7d6a5f4e3c2b1a0987654321fedcba",
		"branch":  "main",
	}, sampleArchive(t), secret)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())

	var queued httpapi.Analysis
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &queued))

	final := waitForTerminal(t, h, queued.ID, secret)
	require.Equal(t, httpapi.StatusCompleted, final.Status, final.Error)
	assert.Equal(t, httpapi.SourceUpload, final.Source)
	assert.Equal(t, "9f2a1c4e8b7d6a5f4e3c2b1a0987654321fedcba", final.Commit)

	sarif := do(t, h, http.MethodGet, "/api/v1/analyses/"+queued.ID+"/sarif", "", secret)
	require.Equal(t, http.StatusOK, sarif.Code, sarif.Body.String())
	assert.Contains(t, sarif.Body.String(), `"version"`,
		"the SARIF must come back out of the database, not just be written to it")

	listed := do(t, h, http.MethodGet, "/api/v1/analyses?project="+project, "", secret)
	require.Equal(t, http.StatusOK, listed.Code)

	var page struct {
		Analyses []httpapi.Analysis `json:"analyses"`
		Count    int                `json:"count"`
	}
	require.NoError(t, json.Unmarshal(listed.Body.Bytes(), &page))
	require.Equal(t, 1, page.Count, "the project filter must reach the database")
	assert.Equal(t, queued.ID, page.Analyses[0].ID)
}

// A key revoked in the database stops working against a running server, with
// no restart: the server reads the store on every request rather than caching
// the credential list at startup.
func TestPostgresWiring_RevokingAKeyTakesEffectWithoutARestart(t *testing.T) {
	h, secret := serverOnPostgres(t)
	dsn := os.Getenv("CORTEX_TEST_POSTGRES_DSN")

	ok := do(t, h, http.MethodGet, "/api/v1/analyses", "", secret)
	require.Equal(t, http.StatusOK, ok.Code)

	keys, err := apikeys.Open(context.Background(), dsn, t.TempDir())
	require.NoError(t, err)
	defer keys.Close()

	key, _, found := keys.Lookup(context.Background(), secret, time.Now())
	require.True(t, found)
	_, err = keys.Revoke(context.Background(), key.ID, time.Now())
	require.NoError(t, err)

	after := do(t, h, http.MethodGet, "/api/v1/analyses", "", secret)
	assert.Equal(t, http.StatusUnauthorized, after.Code)
}
