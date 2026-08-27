// Package httpapi exposes Cortex as a long-running service.
//
// This is the deployment where the engine lives on one server and clients point
// at it with an API key, instead of every client installing seven scanners in
// its own CI. It is a second primary adapter beside interfaces/cli: both drive
// the same use cases through internal/bootstrap, and neither contains business
// logic.
//
// # Endpoints
//
//	GET  /healthz                                    liveness, unauthenticated
//	POST /api/v1/analyses                            analyse a repository
//	GET  /api/v1/analyses                            list, newest first
//	GET  /api/v1/analyses/{id}                       one analysis
//	GET  /api/v1/analyses/{id}/sarif                 its SARIF document
//	POST /api/v1/scans                               ingest SARIF from a client's CI
//	GET  /api/v1/projects/{project}/vulnerabilities  tracked state
//	PUT  /api/v1/projects/{project}/vulnerabilities  replace it
//
// Every call except /healthz needs `Authorization: Bearer <api key>`.
package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/bootstrap"
	"github.com/vektcore/cortex/internal/infrastructure/config"
	gitinfra "github.com/vektcore/cortex/internal/infrastructure/git"
)

// Server is the HTTP adapter.
type Server struct {
	cfg    *config.Config
	store  *Store
	runner *Runner
	auth   *authenticator
	logger ports.Logger
	mux    *http.ServeMux
}

// ErrNoAPIKeys is returned when the server would accept unauthenticated calls.
var ErrNoAPIKeys = errors.New(
	"server.api_keys is empty: refusing to start an unauthenticated service " +
		"that can clone repositories")

// New builds the server. It fails rather than starting without credentials.
func New(cfg *config.Config, logger ports.Logger) (*Server, error) {
	auth := newAuthenticator(cfg.Server.APIKeys)
	if !auth.configured() {
		return nil, ErrNoAPIKeys
	}

	store, err := NewStore(cfg.Server.DataDir)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:    cfg,
		store:  store,
		runner: NewRunner(cfg, store, logger, cfg.Server.Workers),
		auth:   auth,
		logger: logger,
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

// Handler returns the authenticated handler tree.
func (s *Server) Handler() http.Handler { return s.middleware(s.mux) }

// Close stops accepting new analyses.
func (s *Server) Close() { s.runner.Stop() }

// Clients returns how many credentials are configured, for the startup log.
func (s *Server) Clients() int { return len(s.auth.keys) }

func (s *Server) routes() {
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/api/v1/analyses", s.handleAnalyses)
	s.mux.HandleFunc("/api/v1/analyses/", s.handleAnalysisByID)
	s.mux.HandleFunc("/api/v1/scans", s.handleIngestScan)
	s.mux.HandleFunc("/api/v1/projects/", s.handleProjectState)
}

// ---------- health ----------

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------- analyses ----------

type analysisRequest struct {
	Repository string `json:"repository"`
	Ref        string `json:"ref"`
	Project    string `json:"project"`
}

func (s *Server) handleAnalyses(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.createAnalysis(w, r)
	case http.MethodGet:
		s.listAnalyses(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "use POST to submit or GET to list")
	}
}

func (s *Server) createAnalysis(w http.ResponseWriter, r *http.Request) {
	var req analysisRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "body must be JSON: "+err.Error())
		return
	}

	req.Repository = strings.TrimSpace(req.Repository)
	if req.Repository == "" {
		writeError(w, http.StatusBadRequest, `"repository" is required`)
		return
	}
	// Only a remote URL makes sense here: a path would refer to the server's
	// own disk, which is not the caller's to scan.
	if !gitinfra.IsRemoteURL(req.Repository) {
		writeError(w, http.StatusBadRequest,
			`"repository" must be a git URL, e.g. github.com/org/repo`)
		return
	}
	if strings.TrimSpace(req.Project) == "" {
		// Without a project the analysis has no history to compare against.
		req.Project = projectFromRepository(req.Repository)
	}

	analysis := Analysis{
		ID:          bootstrap.RandomIDGen{}.NewScanID().String(),
		Project:     req.Project,
		Repository:  req.Repository,
		Ref:         strings.TrimSpace(req.Ref),
		Status:      StatusQueued,
		RequestedBy: r.Header.Get(clientNameHeader),
		QueuedAt:    time.Now().UTC(),
	}

	if err := s.store.SaveAnalysis(analysis); err != nil {
		s.logger.Error("could not queue analysis", logField("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "could not queue the analysis")
		return
	}
	if !s.runner.Enqueue(analysis.ID) {
		analysis.Status = StatusFailed
		analysis.Error = "the queue is full"
		_ = s.store.SaveAnalysis(analysis)
		writeError(w, http.StatusServiceUnavailable,
			"the queue is full; retry shortly")
		return
	}

	s.logger.Info("analysis queued",
		logField("id", analysis.ID),
		logField("project", analysis.Project),
		logField("client", analysis.RequestedBy))

	w.Header().Set("Location", "/api/v1/analyses/"+analysis.ID)
	writeJSON(w, http.StatusAccepted, analysis)
}

func (s *Server) listAnalyses(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	items, err := s.store.ListAnalyses(r.URL.Query().Get("project"), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"analyses": items,
		"count":    len(items),
	})
}

// handleAnalysisByID serves /api/v1/analyses/{id} and .../{id}/sarif.
func (s *Server) handleAnalysisByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "read-only endpoint")
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/analyses/")
	id, wantSARIF := rest, false
	if strings.HasSuffix(rest, "/sarif") {
		id, wantSARIF = strings.TrimSuffix(rest, "/sarif"), true
	}
	id = sanitizeSegment(strings.Trim(id, "/"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing analysis id")
		return
	}

	analysis, found, err := s.store.LoadAnalysis(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "no analysis with id "+id)
		return
	}

	if !wantSARIF {
		writeJSON(w, http.StatusOK, analysis)
		return
	}

	doc, ok, readErr := s.store.ReadBlob(s.store.SarifPath(id))
	if readErr != nil {
		writeError(w, http.StatusInternalServerError, readErr.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound,
			"no SARIF for "+id+" (status: "+analysis.Status+")")
		return
	}
	w.Header().Set("Content-Type", "application/sarif+json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(doc)
}

// ---------- ingest ----------

// handleIngestScan accepts a SARIF document produced by a client's own CI —
// the other deployment shape, where the scanners run on their runner and only
// the results travel.
func (s *Server) handleIngestScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}

	body, err := readLimited(w, r, 64<<20)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	id := strings.TrimSpace(r.Header.Get("X-Scan-ID"))
	if id == "" {
		id = bootstrap.RandomIDGen{}.NewScanID().String()
	}
	id = sanitizeSegment(id)

	if writeErr := s.store.WriteBlob(s.store.ScanPath(id), body); writeErr != nil {
		writeError(w, http.StatusInternalServerError, "could not store the document")
		return
	}

	s.logger.Info("scan ingested",
		logField("id", id),
		logField("bytes", fmt.Sprint(len(body))),
		logField("client", r.Header.Get(clientNameHeader)))

	writeJSON(w, http.StatusCreated, map[string]string{
		"id":  id,
		"url": "/api/v1/scans/" + id,
	})
}

// ---------- project state ----------

// handleProjectState is the server side of the remote state backend: the two
// calls that let a client's CI keep its history here instead of in its repo.
func (s *Server) handleProjectState(w http.ResponseWriter, r *http.Request) {
	project := projectFromStatePath(r.URL.Path)
	if project == "" {
		writeError(w, http.StatusNotFound, "expected /api/v1/projects/{project}/vulnerabilities")
		return
	}
	path := s.store.ProjectStatePath(project)

	switch r.Method {
	case http.MethodGet:
		doc, ok, err := s.store.ReadBlob(path)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !ok {
			// No history yet. The client reads this as a first scan.
			writeError(w, http.StatusNotFound, "project "+project+" has no state yet")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(doc)

	case http.MethodPut:
		body, err := readLimited(w, r, 64<<20)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		var probe struct {
			Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
		}
		if json.Unmarshal(body, &probe) != nil {
			writeError(w, http.StatusBadRequest, "body is not a state document")
			return
		}
		if writeErr := s.store.WriteBlob(path, body); writeErr != nil {
			writeError(w, http.StatusInternalServerError, "could not store the state")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"project":         project,
			"vulnerabilities": len(probe.Vulnerabilities),
		})

	default:
		writeError(w, http.StatusMethodNotAllowed, "use GET or PUT")
	}
}

// ---------- helpers ----------

func projectFromStatePath(path string) string {
	const prefix = "/api/v1/projects/"
	const suffix = "/vulnerabilities"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := strings.TrimSuffix(strings.TrimSuffix(path, "/"), suffix)
	if rest == strings.TrimSuffix(path, "/") {
		return "" // the suffix was missing
	}
	return strings.Trim(strings.TrimPrefix(rest, prefix), "/")
}

// projectFromRepository derives "org-repo" from a git URL, so a caller that
// omits the project still gets a stable history instead of a fresh one.
func projectFromRepository(url string) string {
	trimmed := strings.TrimSuffix(gitinfra.NormalizeURL(url), ".git")
	trimmed = strings.TrimPrefix(trimmed, "https://")
	trimmed = strings.TrimPrefix(trimmed, "http://")
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) >= 2 {
		return sanitizeSegment(parts[len(parts)-2] + "-" + parts[len(parts)-1])
	}
	return sanitizeSegment(trimmed)
}

// readLimited reads a request body with a ceiling, so a client cannot exhaust
// the server's memory with one POST.
func readLimited(w http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	defer func() { _ = r.Body.Close() }()

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if len(body) == 0 {
		return nil, errors.New("empty body")
	}
	return body, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func logField(key, value string) ports.Field { return ports.F(key, value) }
