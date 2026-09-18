package httpapi_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/infrastructure/config"
	"github.com/vektcore/cortex/internal/infrastructure/logging"
	"github.com/vektcore/cortex/internal/interfaces/httpapi"
)

const uploadURL = "/api/v1/analyses/upload"

// newUploadServer returns the handler and its data directory, which the tests
// need to assert on what the server did with the uploaded archive.
func newUploadServer(t *testing.T, tune func(*config.Config)) (http.Handler, string) {
	t.Helper()

	dataDir := t.TempDir()
	cfg := &config.Config{}
	cfg.Server.DataDir = dataDir
	cfg.Server.Workers = 1
	cfg.Server.APIKeys = []config.APIKey{{Name: "test-client", Key: testKey}}
	cfg.Server.Upload.Enabled = true
	cfg.Server.Upload.MaxArchiveBytes = 1 << 20
	cfg.Server.Upload.MaxExtractedBytes = 4 << 20
	cfg.Server.Upload.MaxEntries = 100
	cfg.State.Enabled = true
	if tune != nil {
		tune(cfg)
	}

	srv, err := httpapi.New(cfg, logging.NewNop())
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	return srv.Handler(), dataDir
}

func sampleArchive(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("main.go")
	require.NoError(t, err)
	_, err = f.Write([]byte("package main\n\nfunc main() {}\n"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	return buf.Bytes()
}

// postUpload builds the multipart request a pipeline would send. A nil archive
// omits the file part entirely.
func postUpload(
	t *testing.T, h http.Handler, fields map[string]string, arch []byte, key string,
) *httptest.ResponseRecorder {
	t.Helper()

	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for name, value := range fields {
		require.NoError(t, form.WriteField(name, value))
	}
	if arch != nil {
		part, err := form.CreateFormFile("archive", "src.zip")
		require.NoError(t, err)
		_, err = part.Write(arch)
		require.NoError(t, err)
	}
	require.NoError(t, form.Close())

	req := httptest.NewRequest(http.MethodPost, uploadURL, &body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestUpload_RejectsMissingCredentials(t *testing.T) {
	t.Parallel()
	h, _ := newUploadServer(t, nil)

	rec := postUpload(t, h, map[string]string{"project": "acme"}, sampleArchive(t), "")

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// A deployment that only clones should not also accept uploads it never asked
// for: the endpoint writes client source to disk, so it opts in.
func TestUpload_IsDisabledByDefault(t *testing.T) {
	t.Parallel()
	h, _ := newUploadServer(t, func(c *config.Config) { c.Server.Upload.Enabled = false })

	rec := postUpload(t, h, map[string]string{"project": "acme"}, sampleArchive(t), testKey)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "server.upload.enabled")
}

func TestUpload_ValidatesTheForm(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		fields  map[string]string
		archive []byte
		msg     string
	}{
		"no archive part": {
			map[string]string{"project": "acme"}, nil, "file part named",
		},
		"no project": {
			map[string]string{}, nil, "file part named",
		},
		"empty archive": {
			map[string]string{"project": "acme"}, []byte{}, "empty",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h, _ := newUploadServer(t, nil)

			rec := postUpload(t, h, tc.fields, tc.archive, testKey)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Contains(t, rec.Body.String(), tc.msg)
		})
	}
}

// Without a stable project the history resets every run, and "new findings" —
// the number the pipeline gates on — silently becomes "all findings".
func TestUpload_RequiresAProject(t *testing.T) {
	t.Parallel()
	h, _ := newUploadServer(t, nil)

	rec := postUpload(t, h, map[string]string{}, sampleArchive(t), testKey)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "the key the finding history is kept under")
}

func TestUpload_RejectsAnArchiveOverTheLimit(t *testing.T) {
	t.Parallel()
	h, _ := newUploadServer(t, func(c *config.Config) {
		c.Server.Upload.MaxArchiveBytes = 64
	})

	rec := postUpload(t, h, map[string]string{"project": "acme"}, sampleArchive(t), testKey)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "exceeds")
}

func TestUpload_QueuesTheAnalysis(t *testing.T) {
	t.Parallel()
	h, _ := newUploadServer(t, nil)

	rec := postUpload(t, h, map[string]string{
		"project":    "acme-api",
		"commit":     "9f2a1c4e8b7d6a5f4e3c2b1a0987654321fedcba",
		"branch":     "main",
		"repository": "github.com/acme/api",
	}, sampleArchive(t), testKey)

	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())

	var a httpapi.Analysis
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &a))
	assert.Equal(t, httpapi.SourceUpload, a.Source)
	assert.Equal(t, "test-client/acme-api", a.Project)
	assert.Equal(t, "9f2a1c4e8b7d6a5f4e3c2b1a0987654321fedcba", a.Commit)
	assert.Equal(t, "main", a.Ref)
	assert.Equal(t, "test-client", a.RequestedBy)
	assert.Equal(t, "/api/v1/analyses/"+a.ID, rec.Header().Get("Location"))
}

// A project name is a path segment in the data directory, so it cannot be
// allowed to name one of its own choosing.
func TestUpload_SanitisesTheProjectName(t *testing.T) {
	t.Parallel()
	h, _ := newUploadServer(t, nil)

	rec := postUpload(t, h,
		map[string]string{"project": "../../etc/passwd"}, sampleArchive(t), testKey)

	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())

	var a httpapi.Analysis
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &a))

	// The key is "<owner>/<name>" now, so the one separator the owner scope
	// adds is expected; what must not survive is anything in the name that
	// could climb out of the data directory.
	_, name, found := strings.Cut(a.Project, "/")
	require.True(t, found)
	assert.Equal(t, "test-client", strings.TrimSuffix(a.Project, "/"+name))
	assert.NotContains(t, name, "/")
	assert.NotContains(t, name, "..")
}

func TestUpload_IsPostOnly(t *testing.T) {
	t.Parallel()
	h, _ := newUploadServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, uploadURL, nil)
	req.Header.Set("Authorization", "Bearer "+testKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code,
		"the id route must not swallow /analyses/upload")
}

// The archive is the client's source code. Once the analysis is over it has no
// reason to remain on a server that also holds other clients' work.
func TestUpload_RunsAndThenDeletesTheArchive(t *testing.T) {
	t.Parallel()
	h, dataDir := newUploadServer(t, nil)

	rec := postUpload(t, h,
		map[string]string{"project": "acme-api", "commit": "deadbeefdeadbeef"},
		sampleArchive(t), testKey)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())

	var queued httpapi.Analysis
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &queued))

	final := waitForTerminal(t, h, queued.ID, testKey)

	assert.Equal(t, httpapi.StatusCompleted, final.Status, final.Error)
	assert.Equal(t, "deadbeefdeadbeef", final.Commit,
		"an uploaded tree has no .git, so the declared revision has to survive")
	assert.NoFileExists(t, filepath.Join(dataDir, "archives", queued.ID+".zip"))
}

func waitForTerminal(t *testing.T, h http.Handler, id, key string) httpapi.Analysis {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		rec := do(t, h, http.MethodGet, "/api/v1/analyses/"+id, "", key)
		require.Equal(t, http.StatusOK, rec.Code)

		var a httpapi.Analysis
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &a))
		if a.Status == httpapi.StatusCompleted || a.Status == httpapi.StatusFailed {
			return a
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("analysis %s never reached a terminal state", id)
	return httpapi.Analysis{}
}
