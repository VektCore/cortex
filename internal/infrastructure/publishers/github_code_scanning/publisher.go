// Package github_code_scanning publishes results back into GitHub itself.
//
// This is what lets a repository be analysed without anything installed in it.
// The server scans a clone and then writes the outcome to GitHub through its
// API: the findings become Code Scanning alerts, annotated on the lines they
// belong to, and the gate verdict becomes a commit status. The repository has no
// workflow, no configuration and no scanners — it only granted read access and
// a push webhook.
//
// Two calls, deliberately separate:
//
//	POST /repos/{owner}/{repo}/code-scanning/sarifs   the findings
//	POST /repos/{owner}/{repo}/statuses/{sha}         the verdict
//
// The findings are worth having even when the status cannot be set (a token
// without statuses:write), and the verdict is worth having even when Code
// Scanning refuses the document (a private repository without GitHub Advanced
// Security). Neither failure is allowed to take the other down.
package github_code_scanning

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultAPI     = "https://api.github.com"
	defaultTimeout = 30 * time.Second
	// statusContext is the name that shows up next to the commit, the way
	// "SonarCloud Code Analysis" does.
	statusContext = "cortex/sast"
)

// Client talks to one GitHub instance.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// New returns a client. An empty baseURL means github.com; set it for GitHub
// Enterprise Server.
func New(baseURL, token string) *Client {
	if baseURL == "" {
		baseURL = defaultAPI
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: defaultTimeout},
	}
}

// Configured reports whether the client has a credential to work with.
func (c *Client) Configured() bool { return strings.TrimSpace(c.token) != "" }

// UploadRequest describes one SARIF upload.
type UploadRequest struct {
	Owner  string
	Repo   string
	Commit string // full 40-character SHA; GitHub rejects anything shorter
	Ref    string // refs/heads/master
	SARIF  []byte
}

// UploadSARIF sends the findings to Code Scanning.
//
// The payload is gzipped and base64-encoded because that is what the endpoint
// accepts — not a courtesy, a requirement.
func (c *Client) UploadSARIF(ctx context.Context, req UploadRequest) error {
	if err := req.validate(); err != nil {
		return err
	}

	packed, err := gzipBase64(req.SARIF)
	if err != nil {
		return err
	}

	body, err := json.Marshal(map[string]string{
		"commit_sha": req.Commit,
		"ref":        req.Ref,
		"sarif":      packed,
	})
	if err != nil {
		return fmt.Errorf("github: encode upload: %w", err)
	}

	url := fmt.Sprintf("%s/repos/%s/%s/code-scanning/sarifs", c.baseURL, req.Owner, req.Repo)
	return c.post(ctx, url, body, "upload SARIF")
}

// StatusRequest describes one commit status.
type StatusRequest struct {
	Owner       string
	Repo        string
	Commit      string
	Passed      bool
	Description string
	TargetURL   string
}

// SetCommitStatus publishes the gate verdict against the commit, so it shows up
// on the commit and on any pull request containing it.
func (c *Client) SetCommitStatus(ctx context.Context, req StatusRequest) error {
	if req.Owner == "" || req.Repo == "" || req.Commit == "" {
		return fmt.Errorf("github: owner, repo and commit are required")
	}

	state := "failure"
	if req.Passed {
		state = "success"
	}

	payload := map[string]string{
		"state":       state,
		"context":     statusContext,
		"description": truncate(req.Description, 140), // GitHub's limit
	}
	if req.TargetURL != "" {
		payload["target_url"] = req.TargetURL
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("github: encode status: %w", err)
	}

	url := fmt.Sprintf("%s/repos/%s/%s/statuses/%s", c.baseURL, req.Owner, req.Repo, req.Commit)
	return c.post(ctx, url, body, "set commit status")
}

func (r UploadRequest) validate() error {
	switch {
	case r.Owner == "" || r.Repo == "":
		return fmt.Errorf("github: owner and repo are required")
	case len(r.Commit) != 40:
		// A short SHA is silently rejected by the API with a generic message;
		// saying so here saves the reader a round trip.
		return fmt.Errorf("github: commit must be a full 40-character SHA, got %q", r.Commit)
	case r.Ref == "":
		return fmt.Errorf("github: ref is required (e.g. refs/heads/main)")
	case len(r.SARIF) == 0:
		return fmt.Errorf("github: nothing to upload")
	}
	return nil
}

func (c *Client) post(ctx context.Context, url string, body []byte, what string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("github: build %s request: %w", what, err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("github: %s: %w", what, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	detail, _ := io.ReadAll(io.LimitReader(resp.Body, 400))
	return fmt.Errorf("github: %s: %s: %s",
		what, resp.Status, strings.TrimSpace(string(detail)))
}

// gzipBase64 is the encoding the Code Scanning endpoint requires.
func gzipBase64(raw []byte) (string, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(raw); err != nil {
		return "", fmt.Errorf("github: compress SARIF: %w", err)
	}
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("github: compress SARIF: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// SlugFromURL pulls "owner", "repo" out of any GitHub clone URL — https, ssh or
// the bare host/owner/repo form. It reports false for anything that is not
// GitHub, so a GitLab target does not get published to the wrong place.
func SlugFromURL(raw string) (owner, repo string, ok bool) {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.TrimSuffix(trimmed, ".git")
	trimmed = strings.TrimSuffix(trimmed, "/")

	switch {
	case strings.HasPrefix(trimmed, "git@"):
		// git@github.com:owner/repo
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 || !strings.Contains(parts[0], "github.com") {
			return "", "", false
		}
		trimmed = parts[1]
	default:
		for _, prefix := range []string{"https://", "http://", "ssh://git@", "ssh://"} {
			trimmed = strings.TrimPrefix(trimmed, prefix)
		}
		if !strings.HasPrefix(trimmed, "github.com/") {
			return "", "", false
		}
		trimmed = strings.TrimPrefix(trimmed, "github.com/")
	}

	segments := strings.Split(trimmed, "/")
	if len(segments) < 2 || segments[0] == "" || segments[1] == "" {
		return "", "", false
	}
	return segments[0], segments[1], true
}

func truncate(text string, max int) string {
	runes := []rune(text)
	if len(runes) <= max {
		return text
	}
	return string(runes[:max-1]) + "…"
}
