package github_code_scanning_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gh "github.com/vektcore/cortex/internal/infrastructure/publishers/github_code_scanning"
)

const fullSHA = "0123456789abcdef0123456789abcdef01234567"

func TestSlugFromURL(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		url         string
		owner, repo string
		ok          bool
	}{
		"bare host form":  {"github.com/punixxher/financeApp", "punixxher", "financeApp", true},
		"https with .git": {"https://github.com/acme/api.git", "acme", "api", true},
		"https plain":     {"https://github.com/acme/api", "acme", "api", true},
		"scp-style ssh":   {"git@github.com:acme/api.git", "acme", "api", true},
		"ssh scheme":      {"ssh://git@github.com/acme/api.git", "acme", "api", true},
		"trailing slash":  {"https://github.com/acme/api/", "acme", "api", true},
		// Publishing a GitLab project's findings to GitHub would be worse than
		// not publishing them.
		"gitlab":       {"https://gitlab.com/acme/api.git", "", "", false},
		"self-hosted":  {"https://git.internal/acme/api.git", "", "", false},
		"owner only":   {"github.com/acme", "", "", false},
		"not a URL":    {"nonsense", "", "", false},
		"empty string": {"", "", "", false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			owner, repo, ok := gh.SlugFromURL(tc.url)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.owner, owner)
			assert.Equal(t, tc.repo, repo)
		})
	}
}

func TestClient_Configured(t *testing.T) {
	t.Parallel()

	assert.False(t, gh.New("", "").Configured())
	assert.False(t, gh.New("", "   ").Configured())
	assert.True(t, gh.New("", "ghp_token").Configured())
}

// The endpoint takes the document gzipped and base64-encoded. That is a
// requirement, not a courtesy: raw SARIF is rejected.
func TestUploadSARIF_SendsGzippedBase64(t *testing.T) {
	t.Parallel()

	var got struct {
		CommitSHA string `json:"commit_sha"`
		Ref       string `json:"ref"`
		SARIF     string `json:"sarif"`
	}
	var gotPath, gotAuth, gotVersion string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotVersion = r.Header.Get("X-GitHub-Api-Version")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	original := []byte(`{"version":"2.1.0","runs":[]}`)
	err := gh.New(srv.URL, "ghp_token").UploadSARIF(context.Background(), gh.UploadRequest{
		Owner: "acme", Repo: "api", Commit: fullSHA, Ref: "refs/heads/main", SARIF: original,
	})
	require.NoError(t, err)

	assert.Equal(t, "/repos/acme/api/code-scanning/sarifs", gotPath)
	assert.Equal(t, "Bearer ghp_token", gotAuth)
	assert.Equal(t, "2022-11-28", gotVersion)
	assert.Equal(t, fullSHA, got.CommitSHA)
	assert.Equal(t, "refs/heads/main", got.Ref)

	decoded, err := base64.StdEncoding.DecodeString(got.SARIF)
	require.NoError(t, err, "the payload must be base64")

	reader, err := gzip.NewReader(bytes.NewReader(decoded))
	require.NoError(t, err, "the payload must be gzipped")
	unpacked, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.JSONEq(t, string(original), string(unpacked),
		"what arrives must be exactly what was scanned")
}

// A short SHA is rejected by the API with a generic message; catching it here
// says which field is wrong.
func TestUploadSARIF_RejectsIncompleteInput(t *testing.T) {
	t.Parallel()

	client := gh.New("https://api.example.com", "t")
	valid := gh.UploadRequest{
		Owner: "acme", Repo: "api", Commit: fullSHA,
		Ref: "refs/heads/main", SARIF: []byte("{}"),
	}

	tests := map[string]func(r gh.UploadRequest) gh.UploadRequest{
		"no owner":    func(r gh.UploadRequest) gh.UploadRequest { r.Owner = ""; return r },
		"short SHA":   func(r gh.UploadRequest) gh.UploadRequest { r.Commit = "abc123"; return r },
		"no ref":      func(r gh.UploadRequest) gh.UploadRequest { r.Ref = ""; return r },
		"empty SARIF": func(r gh.UploadRequest) gh.UploadRequest { r.SARIF = nil; return r },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			err := client.UploadSARIF(context.Background(), mutate(valid))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "github:")
		})
	}
}

// A repository without GitHub Advanced Security refuses the upload. The error
// has to carry the server's explanation, or the operator has nothing to act on.
func TestUploadSARIF_SurfacesTheAPIError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Advanced Security must be enabled for this repository."}`))
	}))
	defer srv.Close()

	err := gh.New(srv.URL, "t").UploadSARIF(context.Background(), gh.UploadRequest{
		Owner: "acme", Repo: "api", Commit: fullSHA,
		Ref: "refs/heads/main", SARIF: []byte("{}"),
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
	assert.Contains(t, err.Error(), "Advanced Security must be enabled")
}

func TestSetCommitStatus_PassAndFail(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		passed    bool
		wantState string
	}{
		{"gate passed", true, "success"},
		{"gate failed", false, "failure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got map[string]string
			var gotPath string

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &got)
				w.WriteHeader(http.StatusCreated)
			}))
			defer srv.Close()

			err := gh.New(srv.URL, "t").SetCommitStatus(context.Background(), gh.StatusRequest{
				Owner: "acme", Repo: "api", Commit: fullSHA,
				Passed:      tc.passed,
				Description: "3 new, 61 total, 4 scanner(s)",
				TargetURL:   "https://sast.example.com/api/v1/analyses/abc",
			})
			require.NoError(t, err)

			assert.Equal(t, "/repos/acme/api/statuses/"+fullSHA, gotPath)
			assert.Equal(t, tc.wantState, got["state"])
			assert.Equal(t, "cortex/sast", got["context"])
			assert.Equal(t, "3 new, 61 total, 4 scanner(s)", got["description"])
			assert.Equal(t, "https://sast.example.com/api/v1/analyses/abc", got["target_url"])
		})
	}
}

// GitHub truncates a description over 140 characters and returns a validation
// error for some payloads; trimming it here keeps the status publishable.
func TestSetCommitStatus_TruncatesLongDescriptions(t *testing.T) {
	t.Parallel()

	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	long := ""
	for i := 0; i < 40; i++ {
		long += "findings "
	}

	err := gh.New(srv.URL, "t").SetCommitStatus(context.Background(), gh.StatusRequest{
		Owner: "acme", Repo: "api", Commit: fullSHA, Description: long,
	})
	require.NoError(t, err)
	assert.LessOrEqual(t, len([]rune(got["description"])), 140)
}
