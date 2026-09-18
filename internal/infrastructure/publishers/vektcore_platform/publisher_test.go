package vektcore_platform_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platform "github.com/vektcore/cortex/internal/infrastructure/publishers/vektcore_platform"
)

const (
	projectUUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	testToken   = "eyJhbGciOiJIUzI1NiJ9.payload.signature"
	sampleSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"cortex"}},"results":[]}]}`
)

// wire mirrors the endpoint's SubmitScanRequest so the test asserts the real
// field names, not the ones this package happens to produce.
type wire struct {
	ProjectID string          `json:"project_id"`
	SARIF     json.RawMessage `json:"sarif"`
	Metadata  struct {
		Branch         string `json:"branch"`
		CommitSHA      string `json:"commit_sha"`
		Author         string `json:"author"`
		PipelineID     string `json:"pipeline_id"`
		ScannerName    string `json:"scanner_name"`
		ScannerVersion string `json:"scanner_version"`
	} `json:"metadata"`
}

func validRequest() platform.ScanRequest {
	return platform.ScanRequest{
		ProjectID:      projectUUID,
		Commit:         "0123456789abcdef0123456789abcdef01234567",
		Ref:            "refs/heads/develop",
		Author:         "daniel",
		AnalysisID:     "an_01J9",
		ScannerVersion: "1.4.2",
		SARIF:          []byte(sampleSARIF),
	}
}

func TestClient_Configured(t *testing.T) {
	t.Parallel()

	assert.False(t, platform.New("", "").Configured())
	assert.False(t, platform.New("https://api.example.com", "  ").Configured(), "token missing")
	assert.False(t, platform.New("", "token").Configured(), "base URL missing")
	assert.True(t, platform.New("https://api.example.com", "token").Configured())
}

func TestPublishScan_SendsTheContractTheGatewayExpects(t *testing.T) {
	t.Parallel()

	var got wire
	var gotPath, gotMethod, gotAuth, gotContentType string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated) // the endpoint answers 201, not 200
		_, _ = w.Write([]byte(`{
			"id":"9c6f1a2e-0000-4000-8000-000000000001",
			"project_id":"` + projectUUID + `",
			"status":"completed",
			"total_findings":61,"new_findings":3,"existing_findings":58,
			"false_positives_count":2,
			"pipeline_result":"passed","pipeline_reason":"under threshold"
		}`))
	}))
	defer srv.Close()

	result, err := platform.New(srv.URL, testToken).
		PublishScan(context.Background(), validRequest())
	require.NoError(t, err)

	assert.Equal(t, "/api/v1/sast/scans", gotPath)
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "Bearer "+testToken, gotAuth)
	assert.Equal(t, "application/json", gotContentType)

	assert.Equal(t, projectUUID, got.ProjectID)
	assert.Equal(t, "develop", got.Metadata.Branch, "refs/heads/ is stripped")
	assert.Equal(t, "0123456789abcdef0123456789abcdef01234567", got.Metadata.CommitSHA)
	assert.Equal(t, "daniel", got.Metadata.Author)
	assert.Equal(t, "an_01J9", got.Metadata.PipelineID,
		"the analysis id is what links a platform scan back to the cortex run")
	assert.Equal(t, "cortex", got.Metadata.ScannerName)
	assert.Equal(t, "1.4.2", got.Metadata.ScannerVersion)

	// The field is declared as an object. Sending it as a JSON *string* is
	// accepted by neither the validator nor the processor.
	assert.JSONEq(t, sampleSARIF, string(got.SARIF),
		"what arrives must be exactly what was scanned")

	assert.Equal(t, "9c6f1a2e-0000-4000-8000-000000000001", result.ScanID)
	assert.Equal(t, "completed", result.Status)
	assert.Equal(t, 61, result.TotalFindings)
	assert.Equal(t, 3, result.NewFindings)
	assert.Equal(t, 58, result.ExistingFindings)
	assert.Equal(t, 2, result.FalsePositives)
	assert.Equal(t, "passed", result.PipelineResult)
	assert.Equal(t, "under threshold", result.PipelineReason)
}

func TestPublishScan_NormalisesTheRef(t *testing.T) {
	t.Parallel()

	tests := map[string]struct{ ref, want string }{
		"full ref":         {"refs/heads/main", "main"},
		"slashed branch":   {"refs/heads/release/2.1", "release/2.1"},
		"remote tracking":  {"refs/remotes/origin/main", "main"},
		"already a branch": {"develop", "develop"},
		"empty":            {"", ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var got wire
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &got)
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer srv.Close()

			req := validRequest()
			req.Ref = tc.ref
			_, err := platform.New(srv.URL, testToken).PublishScan(context.Background(), req)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got.Metadata.Branch)
		})
	}
}

// Oversized metadata is trimmed to the platform's column widths. Postgres
// rejects an over-long value instead of truncating it, and it does so only
// after the whole document has been uploaded and processed.
func TestPublishScan_TrimsToTheColumnWidths(t *testing.T) {
	t.Parallel()

	var got wire
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	req := validRequest()
	req.Ref = strings.Repeat("b", 400)
	req.Commit = strings.Repeat("c", 100)
	req.Author = strings.Repeat("a", 400)
	req.AnalysisID = strings.Repeat("p", 400)
	req.ScannerVersion = strings.Repeat("v", 100)

	_, err := platform.New(srv.URL, testToken).PublishScan(context.Background(), req)
	require.NoError(t, err)

	assert.Len(t, got.Metadata.Branch, 255)
	assert.Len(t, got.Metadata.CommitSHA, 64)
	assert.Len(t, got.Metadata.Author, 255)
	assert.Len(t, got.Metadata.PipelineID, 255)
	assert.Len(t, got.Metadata.ScannerVersion, 50)
}

// Bad input is caught before the upload: a multi-megabyte SARIF should not be
// sent across the wire to be told the project id was a name.
func TestPublishScan_RejectsBadInputWithoutCallingTheAPI(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mutate func(r platform.ScanRequest) platform.ScanRequest
		errHas string
	}{
		"project name instead of UUID": {
			func(r platform.ScanRequest) platform.ScanRequest { r.ProjectID = "cortex"; return r },
			"UUID",
		},
		"no project": {
			func(r platform.ScanRequest) platform.ScanRequest { r.ProjectID = ""; return r },
			"UUID",
		},
		"malformed UUID": {
			func(r platform.ScanRequest) platform.ScanRequest {
				r.ProjectID = "3f2504e0-4f89-11d3-9a0c-0305e82c33zz"
				return r
			},
			"UUID",
		},
		"empty SARIF": {
			func(r platform.ScanRequest) platform.ScanRequest { r.SARIF = nil; return r },
			"nothing to publish",
		},
		"SARIF is not JSON": {
			func(r platform.ScanRequest) platform.ScanRequest { r.SARIF = []byte("not json"); return r },
			"JSON object",
		},
		"SARIF is a JSON array": {
			func(r platform.ScanRequest) platform.ScanRequest { r.SARIF = []byte(`[]`); return r },
			"JSON object",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			called := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusCreated)
			}))
			defer srv.Close()

			_, err := platform.New(srv.URL, testToken).
				PublishScan(context.Background(), tc.mutate(validRequest()))

			require.Error(t, err)
			assert.Contains(t, err.Error(), "vektcore platform:")
			assert.Contains(t, err.Error(), tc.errHas)
			assert.False(t, called, "nothing should have been uploaded")
		})
	}
}

// An unconfigured deployment must not produce a request at all — that is what
// lets the caller wire the publisher unconditionally.
func TestPublishScan_UnconfiguredFailsWithoutNetwork(t *testing.T) {
	t.Parallel()

	_, err := platform.New("", "").PublishScan(context.Background(), validRequest())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not configured")
}

// The error is the only place anyone will see why the push failed, so it has
// to carry the status and the platform's own explanation.
func TestPublishScan_SurfacesTheStatusAndBody(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"Module not available in your current plan","module":"code_security"}`))
	}))
	defer srv.Close()

	_, err := platform.New(srv.URL, testToken).
		PublishScan(context.Background(), validRequest())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
	assert.Contains(t, err.Error(), "Module not available in your current plan")
	assert.NotContains(t, err.Error(), testToken, "the token must never reach a log line")
}

// A platform behind a broken proxy answers with a whole HTML error page. All
// of it in one log line buries every other line around it.
func TestPublishScan_TruncatesAHugeErrorBody(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(strings.Repeat("x", 100_000)))
	}))
	defer srv.Close()

	_, err := platform.New(srv.URL, testToken).
		PublishScan(context.Background(), validRequest())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "502")
	assert.Less(t, len(err.Error()), 1000, "the body must be truncated, not pasted whole")
}

// A trailing slash on the configured base URL must not produce a double slash
// in the path: the gateway's route table matches on the exact prefix.
func TestPublishScan_ToleratesATrailingSlashInTheBaseURL(t *testing.T) {
	t.Parallel()

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	_, err := platform.New(srv.URL+"/", testToken).
		PublishScan(context.Background(), validRequest())
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/sast/scans", gotPath)
}

// The scan is already ingested by the time the body is read. Saying that
// plainly stops anyone from re-uploading a document the platform has.
func TestPublishScan_ReportsAnUndecodableSuccessBodyAsSuch(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`<html>proxy ate it</html>`))
	}))
	defer srv.Close()

	_, err := platform.New(srv.URL, testToken).
		PublishScan(context.Background(), validRequest())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "scan accepted")
}
