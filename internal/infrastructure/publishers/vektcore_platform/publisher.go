// Package vektcore_platform pushes a finished analysis into the VektCore
// platform, where the SAST module owns triage.
//
// Cortex keeps its own copy of what a scan found; the platform owns what the
// team decided about it. The push is one-way on purpose: nothing the platform
// records flows back and rewrites a cortex verdict, so the two can disagree
// without either corrupting the other.
//
// One call:
//
//	POST /api/v1/sast/scans   the SARIF document plus the run's metadata
//
// The platform validates the document, deduplicates it against the project's
// existing findings and replays remembered triage decisions onto them, all
// inside that single request. The response is therefore the outcome of
// processing, not an acknowledgement of receipt — which is why the timeout
// here is generous rather than the usual API-call handful of seconds.
//
// Publishing is best-effort by design. See PublishScan.
package vektcore_platform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// defaultTimeout has to cover ingestion, not a round trip: the platform
	// parses every result, deduplicates it and re-applies triage before it
	// answers. A 30s budget times out on a large monorepo's SARIF while the
	// server is still working, and the retry uploads the whole thing again.
	defaultTimeout = 60 * time.Second

	scanPath = "/api/v1/sast/scans"

	// scannerName is what the platform files these scans under, the way
	// "semgrep" or "trivy" would appear for a scan pushed by those tools.
	scannerName = "cortex"

	// Column widths of the platform's sast_scans table. Postgres rejects an
	// over-long value rather than truncating it, and it does so after the
	// whole document has been uploaded and processed — an opaque 500 at the
	// most expensive possible moment. Trimming here is cheaper than finding
	// out there.
	maxBranchLen         = 255
	maxCommitLen         = 64
	maxAuthorLen         = 255
	maxPipelineIDLen     = 255
	maxScannerVersionLen = 50

	// errorBodyLimit caps how much of a failure response ends up in an error.
	// A platform behind a misconfigured proxy answers with an HTML error page,
	// and a whole one of those in a log line buries the actual message.
	errorBodyLimit = 400

	// responseBodyLimit bounds what we are willing to decode on success. The
	// scan summary is a few hundred bytes; anything of this size is a proxy
	// answering in the platform's place.
	responseBodyLimit = 64 << 10
)

// Client talks to one VektCore platform deployment.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// New returns a client for the platform's gateway.
//
// baseURL is the gateway origin (the gateway proxies /api/v1/sast/* to the
// vulnerability service), e.g. "https://api.vektcore.example". token is a JWT
// issued by the platform's identity service.
func New(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		token:   token,
		http:    &http.Client{Timeout: defaultTimeout},
	}
}

// Configured reports whether the client has somewhere to publish to and a
// credential to do it with. A cortex deployment that does not use the platform
// leaves both unset, and the caller skips publishing entirely rather than
// failing a run over an integration nobody asked for.
func (c *Client) Configured() bool {
	return c.baseURL != "" && strings.TrimSpace(c.token) != ""
}

// ScanRequest is one completed analysis, in the terms the platform uses.
//
// The caller maps its own analysis record onto this; the package deliberately
// does not import cortex's Analysis type, so the wire contract stays visible
// in one file and changes to the record do not silently change the payload.
type ScanRequest struct {
	// ProjectID is a sast_projects UUID. The platform addresses projects by
	// UUID only — cortex's own project name is not a substitute, so the
	// name→UUID mapping has to be configured per project.
	ProjectID string
	// Commit is the revision analysed. Optional; the platform stores "".
	Commit string
	// Ref is either a full ref ("refs/heads/main") or a bare branch name.
	// Both are accepted: the platform's column is a branch, so a full ref is
	// reduced to its last component before sending.
	Ref string
	// Author is whoever requested the analysis.
	Author string
	// AnalysisID is cortex's own id for the run. It travels as pipeline_id,
	// which is the only field that lets someone looking at a scan in the
	// platform find the cortex run that produced it.
	AnalysisID string
	// ScannerVersion is the cortex build that produced the document.
	ScannerVersion string
	// SARIF is the document exactly as cortex stored it. The endpoint declares
	// this field as an object, not a string, so it is embedded verbatim rather
	// than encoded into a JSON string.
	SARIF []byte
}

// ScanResult is what the platform reports back about the scan it just
// ingested. Its counts are the platform's, not cortex's: they already have
// deduplication and remembered triage applied, so they legitimately differ
// from what the analysis recorded.
type ScanResult struct {
	ScanID           string `json:"id"`
	ProjectID        string `json:"project_id"`
	Status           string `json:"status"`
	TotalFindings    int    `json:"total_findings"`
	NewFindings      int    `json:"new_findings"`
	ExistingFindings int    `json:"existing_findings"`
	FalsePositives   int    `json:"false_positives_count"`
	PipelineResult   string `json:"pipeline_result"`
	PipelineReason   string `json:"pipeline_reason"`
}

type scanPayload struct {
	ProjectID string          `json:"project_id"`
	SARIF     json.RawMessage `json:"sarif"`
	Metadata  scanMetadata    `json:"metadata"`
}

type scanMetadata struct {
	Branch         string `json:"branch"`
	CommitSHA      string `json:"commit_sha"`
	Author         string `json:"author"`
	PipelineID     string `json:"pipeline_id"`
	ScannerName    string `json:"scanner_name"`
	ScannerVersion string `json:"scanner_version"`
}

// PublishScan uploads the analysis and its SARIF to the platform.
//
// Every failure here is recoverable and non-fatal: by the time this runs the
// analysis has already succeeded and its results are stored in cortex. The
// findings are not lost when the platform is down, misconfigured or slow —
// only mirrored late. The caller is expected to log the returned error and
// swallow it, never to fail the run or change the gate verdict over it. The
// errors are descriptive for exactly that reason: the log line is the only
// place anyone will see them.
func (c *Client) PublishScan(ctx context.Context, req ScanRequest) (ScanResult, error) {
	if !c.Configured() {
		return ScanResult{}, fmt.Errorf("vektcore platform: not configured (base URL and token required)")
	}
	if err := req.validate(); err != nil {
		return ScanResult{}, err
	}

	body, err := json.Marshal(scanPayload{
		ProjectID: req.ProjectID,
		SARIF:     json.RawMessage(req.SARIF),
		Metadata: scanMetadata{
			Branch:         truncate(branchFromRef(req.Ref), maxBranchLen),
			CommitSHA:      truncate(req.Commit, maxCommitLen),
			Author:         truncate(req.Author, maxAuthorLen),
			PipelineID:     truncate(req.AnalysisID, maxPipelineIDLen),
			ScannerName:    scannerName,
			ScannerVersion: truncate(req.ScannerVersion, maxScannerVersionLen),
		},
	})
	if err != nil {
		return ScanResult{}, fmt.Errorf("vektcore platform: encode scan: %w", err)
	}

	raw, err := c.post(ctx, c.baseURL+scanPath, body)
	if err != nil {
		return ScanResult{}, err
	}

	var result ScanResult
	if decodeErr := json.Unmarshal(raw, &result); decodeErr != nil {
		// The scan was accepted; only the summary is unreadable. Say so
		// precisely, so nobody re-uploads a document the platform already has.
		return ScanResult{}, fmt.Errorf(
			"vektcore platform: scan accepted but response could not be decoded: %w", decodeErr)
	}
	return result, nil
}

func (r ScanRequest) validate() error {
	switch {
	case !isUUID(r.ProjectID):
		// The platform parses this as a UUID before it looks anything up, so a
		// project name or an empty string comes back as a 422 about a field
		// the caller never knowingly set.
		return fmt.Errorf("vektcore platform: project ID must be a platform SAST project UUID, got %q", r.ProjectID)
	case len(r.SARIF) == 0:
		return fmt.Errorf("vektcore platform: nothing to publish")
	case !isJSONObject(r.SARIF):
		// The endpoint's field is an object. Sending anything else costs a
		// full upload to be told so.
		return fmt.Errorf("vektcore platform: SARIF must be a JSON object")
	}
	return nil
}

func (c *Client) post(ctx context.Context, url string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("vektcore platform: build scan request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	// The token is a bearer JWT and never goes anywhere but this header: not
	// in the URL, where proxies and access logs would keep it, and not in any
	// error this package returns.
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vektcore platform: submit scan: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyLimit))
		return nil, fmt.Errorf("vektcore platform: submit scan: %s: %s",
			resp.Status, strings.TrimSpace(string(detail)))
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, responseBodyLimit))
	if err != nil {
		return nil, fmt.Errorf("vektcore platform: read scan response: %w", err)
	}
	return raw, nil
}

// branchFromRef reduces a git ref to the branch name the platform stores.
// "refs/heads/release/2.1" is a branch called "release/2.1", so only the
// leading refs/heads/ is dropped — splitting on every slash would rename it.
func branchFromRef(ref string) string {
	trimmed := strings.TrimSpace(ref)
	for _, prefix := range []string{"refs/heads/", "refs/remotes/origin/"} {
		if strings.HasPrefix(trimmed, prefix) {
			return strings.TrimPrefix(trimmed, prefix)
		}
	}
	return trimmed
}

// isUUID checks the 8-4-4-4-12 hex form. Hand-rolled rather than pulled in as
// a dependency: this only has to reject a project *name* sent where a UUID
// belongs, which is the mistake that actually happens.
func isUUID(s string) bool {
	groups := strings.Split(s, "-")
	want := []int{8, 4, 4, 4, 12}
	if len(groups) != len(want) {
		return false
	}
	for i, group := range groups {
		if len(group) != want[i] {
			return false
		}
		for _, r := range group {
			isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}

func isJSONObject(raw []byte) bool {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{' && json.Valid(raw)
}

func truncate(text string, max int) string {
	runes := []rune(text)
	if len(runes) <= max {
		return text
	}
	return string(runes[:max])
}
