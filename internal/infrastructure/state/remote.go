package state

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/domain/vulnerability"
)

// RemoteStore keeps the vulnerability state on a server instead of in a file
// next to the repository.
//
// This is what turns Cortex from a local tool into the client of a platform.
// The file store cannot serve that model: a third party's repository is not
// going to carry our state document, and the triage recorded in it has to be
// visible to whoever runs the platform rather than to whoever clones the repo.
//
// The wire format is byte-identical to the file one, so a project can move
// between backends without a migration.
type RemoteStore struct {
	baseURL string
	token   string
	project string
	client  *http.Client
}

const (
	remoteTimeout   = 30 * time.Second
	projectsPath    = "/api/v1/projects/"
	vulnerabilities = "/vulnerabilities"
)

// NewRemote returns a store talking to baseURL on behalf of one project.
// Validation happens on use rather than here: a misconfigured store must fail
// with a Result the use case can isolate, not at construction time.
func NewRemote(baseURL, token, project string) *RemoteStore {
	return &RemoteStore{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		project: project,
		client:  &http.Client{Timeout: remoteTimeout},
	}
}

// Endpoint is the URL this store reads and writes, mirroring Store.Path.
func (s *RemoteStore) Endpoint() string {
	return s.baseURL + projectsPath + s.project + vulnerabilities
}

// Load fetches the project's state. A 404 is an empty state, not an error: the
// first scan of a project has nothing to remember, exactly as with a missing
// file.
func (s *RemoteStore) Load(ctx context.Context) mo.Result[[]vulnerability.Vulnerability] {
	empty := []vulnerability.Vulnerability{}

	if err := s.validate(); err != nil {
		return shared.Err[[]vulnerability.Vulnerability](err)
	}

	body, status, err := s.do(ctx, http.MethodGet, nil)
	if err != nil {
		return shared.Err[[]vulnerability.Vulnerability](err)
	}
	if status == http.StatusNotFound {
		return shared.Ok(empty)
	}
	if status < 200 || status >= 300 {
		return shared.Err[[]vulnerability.Vulnerability](s.statusErr("load", status, body))
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return shared.Ok(empty)
	}

	vulns, decodeErr := decodeState(body, s.Endpoint())
	if decodeErr != nil {
		return shared.Err[[]vulnerability.Vulnerability](decodeErr)
	}
	return shared.Ok(vulns)
}

// Save replaces the project's stored state. PUT rather than POST because the
// document is the whole state: sending it twice has to leave the server in the
// same place, so a retried CI job cannot duplicate anybody's triage.
func (s *RemoteStore) Save(
	ctx context.Context, vulns []vulnerability.Vulnerability,
) mo.Result[int] {
	if err := s.validate(); err != nil {
		return shared.Err[int](err)
	}

	encoded, err := encodeState(vulns)
	if err != nil {
		return shared.Err[int](err)
	}

	body, status, err := s.do(ctx, http.MethodPut, encoded)
	if err != nil {
		return shared.Err[int](err)
	}
	if status < 200 || status >= 300 {
		return shared.Err[int](s.statusErr("save", status, body))
	}
	return shared.Ok(len(vulns))
}

// validate rejects a store that cannot possibly work, with a message that says
// which key is missing rather than surfacing a bare URL parse error later.
func (s *RemoteStore) validate() error {
	if s.baseURL == "" {
		return fmt.Errorf("state: remote backend selected but state.remote.url is empty")
	}
	if s.project == "" {
		return fmt.Errorf("state: remote backend selected but state.remote.project is empty")
	}
	return nil
}

func (s *RemoteStore) do(
	ctx context.Context, method string, payload []byte,
) ([]byte, int, error) {
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, s.Endpoint(), reader)
	if err != nil {
		return nil, 0, fmt.Errorf("state: build %s request: %w", method, err)
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("state: %s %s: %w", method, s.Endpoint(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("state: read response: %w", err)
	}
	return body, resp.StatusCode, nil
}

// statusErr includes a slice of the server's own message: "server returned 403"
// alone sends the reader to the wrong place.
func (s *RemoteStore) statusErr(op string, status int, body []byte) error {
	detail := strings.TrimSpace(string(body))
	const maxDetail = 200
	if len(detail) > maxDetail {
		detail = detail[:maxDetail] + "…"
	}
	if detail == "" {
		return fmt.Errorf("state: %s: server returned %d", op, status)
	}
	return fmt.Errorf("state: %s: server returned %d: %s", op, status, detail)
}
