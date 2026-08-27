// Package korvlabs publishes scan results to the KorvLabs security platform.
// It POSTs SARIF to the configured endpoint and returns a receipt with the
// server-assigned scan URL.
package korvlabs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/shared"
)

const (
	defaultTimeout   = 30 * time.Second
	scanEndpointPath = "/api/v1/scans"
	contentTypeSARIF = "application/sarif+json"
)

// Publisher implements ports.Publisher by sending SARIF to the KorvLabs API.
type Publisher struct {
	url    string
	apiKey string
	client *http.Client
}

// New returns a Publisher targeting url with the given API key.
// A zero-duration timeout falls back to defaultTimeout.
func New(url, apiKey string) *Publisher {
	return &Publisher{
		url:    url,
		apiKey: apiKey,
		client: &http.Client{Timeout: defaultTimeout},
	}
}

func (p *Publisher) Name() string { return "korvlabs" }

// Publish POSTs req.SARIF to <url>/api/v1/scans.
// On success the server returns JSON {"id":"...", "url":"..."}.
func (p *Publisher) Publish(
	ctx context.Context,
	req ports.PublishRequest,
) mo.Result[ports.PublishReceipt] {
	endpoint := p.url + scanEndpointPath

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		bytes.NewReader(req.SARIF))
	if err != nil {
		return shared.Err[ports.PublishReceipt](
			fmt.Errorf("korvlabs: build request: %w", err))
	}
	httpReq.Header.Set("Content-Type", contentTypeSARIF)
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	if scanID := req.ScanID.String(); scanID != "" {
		httpReq.Header.Set("X-Scan-ID", scanID)
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return shared.Err[ports.PublishReceipt](
			fmt.Errorf("korvlabs: POST %s: %w", endpoint, err))
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return shared.Err[ports.PublishReceipt](
			fmt.Errorf("korvlabs: server returned %d", resp.StatusCode))
	}

	var body struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if jsonErr := json.NewDecoder(resp.Body).Decode(&body); jsonErr != nil {
		// Non-fatal: receipt without a reference is still a success.
		return shared.Ok(ports.PublishReceipt{
			Publisher: "korvlabs",
			Reference: endpoint,
		})
	}

	ref := body.URL
	if ref == "" {
		ref = body.ID
	}
	if ref == "" {
		ref = endpoint
	}
	return shared.Ok(ports.PublishReceipt{
		Publisher: "korvlabs",
		Reference: ref,
	})
}
