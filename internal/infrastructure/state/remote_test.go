package state_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/domain/vulnerability"
	"github.com/vektcore/cortex/internal/infrastructure/state"
)

func TestRemoteStore_Endpoint(t *testing.T) {
	t.Parallel()

	s := state.NewRemote("https://api.example.com/", "tok", "acme-api")

	assert.Equal(t,
		"https://api.example.com/api/v1/projects/acme-api/vulnerabilities",
		s.Endpoint(),
		"a trailing slash on the base URL must not double up in the path")
}

// The first scan of a project has no history: a 404 is an empty state, exactly
// as a missing file is for the local backend. Treating it as an error would
// make every project fail on its first run.
func TestRemoteStore_LoadMissingProjectIsEmpty(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	vulns, err := state.NewRemote(srv.URL, "tok", "p").
		Load(context.Background()).Get()

	require.NoError(t, err)
	assert.Empty(t, vulns)
}

// A server that answers "{}" has also stored nothing yet, and must not trip the
// format-version check.
func TestRemoteStore_LoadEmptyDocumentIsEmpty(t *testing.T) {
	t.Parallel()

	for _, body := range []string{"", "{}", `{"vulnerabilities":[]}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))

		vulns, err := state.NewRemote(srv.URL, "tok", "p").
			Load(context.Background()).Get()
		srv.Close()

		require.NoError(t, err, "body %q must read as an empty state", body)
		assert.Empty(t, vulns)
	}
}

// Save must PUT the same document the file backend writes, so a project can
// move between backends without a migration — and carry the token.
func TestRemoteStore_SaveRoundTrip(t *testing.T) {
	t.Parallel()

	var (
		gotMethod string
		gotPath   string
		gotAuth   string
		gotCT     string
		gotBody   []byte
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	now := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	stored := []vulnerability.Vulnerability{
		mkVuln(t, "app/db.py", "get_user", now),
		mkVuln(t, "app/api.py", "handler", now),
	}

	count, err := state.NewRemote(srv.URL, "secret-token", "acme-api").
		Save(context.Background(), stored).Get()

	require.NoError(t, err)
	assert.Equal(t, len(stored), count)

	assert.Equal(t, http.MethodPut, gotMethod,
		"the document is the whole state, so writing it twice must be idempotent")
	assert.Equal(t, "/api/v1/projects/acme-api/vulnerabilities", gotPath)
	assert.Equal(t, "Bearer secret-token", gotAuth)
	assert.Equal(t, "application/json", gotCT)

	var doc struct {
		Version         int `json:"version"`
		Vulnerabilities []struct {
			Exact  string `json:"exact"`
			RuleID string `json:"rule_id"`
		} `json:"vulnerabilities"`
	}
	require.NoError(t, json.Unmarshal(gotBody, &doc))
	assert.Equal(t, 1, doc.Version, "the wire format must match the file format")
	require.Len(t, doc.Vulnerabilities, len(stored))
	assert.NotEmpty(t, doc.Vulnerabilities[0].Exact)
}

// A state the server rejects has to surface, with the server's own words: a
// bare "returned 403" sends the reader looking in the wrong place.
func TestRemoteStore_ServerErrorSurfaces(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"project token revoked"}`))
	}))
	defer srv.Close()

	_, err := state.NewRemote(srv.URL, "tok", "p").
		Load(context.Background()).Get()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
	assert.Contains(t, err.Error(), "project token revoked")
}

// Misconfiguration must name the missing key rather than failing later with an
// opaque URL error.
func TestRemoteStore_MisconfigurationIsExplicit(t *testing.T) {
	t.Parallel()

	_, noURL := state.NewRemote("", "tok", "p").Load(context.Background()).Get()
	require.Error(t, noURL)
	assert.Contains(t, noURL.Error(), "state.remote.url")

	_, noProject := state.NewRemote("https://api.example.com", "tok", "").
		Load(context.Background()).Get()
	require.Error(t, noProject)
	assert.Contains(t, noProject.Error(), "state.remote.project")
}
