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
//	POST /api/v1/analyses/upload                     analyse an uploaded archive
//	GET  /api/v1/analyses                            list, newest first
//	GET  /api/v1/analyses/{id}                       one analysis
//	GET  /api/v1/analyses/{id}/sarif                 its SARIF document
//	POST /api/v1/scans                               ingest SARIF from a client's CI
//	GET  /api/v1/projects/{project}/vulnerabilities  tracked state
//	PUT  /api/v1/projects/{project}/vulnerabilities  replace it
//
// Every call except /healthz needs `Authorization: Bearer <api key>`.
//
// # Tenancy
//
// The key does not only say "a client"; it says *which* client, and every
// handler here scopes what it reads and writes to that client. A record owned
// by somebody else is answered 404, never 403 — a 403 confirms the resource
// exists, which turns the id space into an oracle for enumerating another
// client's analyses. Ownership itself lives in tenancy.go.
//
// Project names stay bare in the URL and in ?project=, and are resolved inside
// the caller's namespace, so nothing a client's pipeline sends has to change.
// A caller the operator has elevated (CORTEX_SERVER_ADMIN_CLIENTS) sees every
// tenant and may narrow with ?owner=.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/bootstrap"
	"github.com/vektcore/cortex/internal/infrastructure/apikeys"
	"github.com/vektcore/cortex/internal/infrastructure/config"
	gitinfra "github.com/vektcore/cortex/internal/infrastructure/git"
)

// Server is the HTTP adapter.
type Server struct {
	cfg     *config.Config
	store   *Store
	records analysisRecords
	issued  apikeys.Repository
	runner  *Runner
	auth    *authenticator
	logger  ports.Logger
	mux     *http.ServeMux
	// adminClients are the client names the operator elevated to read every
	// tenant's records. Resolved once at startup from the environment, so a
	// request can never talk its way into the set. Empty by default.
	adminClients map[string]struct{}
}

// ErrNoAPIKeys is returned when nobody could authenticate against this server.
var ErrNoAPIKeys = errors.New(
	"no usable API key: refusing to start a service that would answer 401 to " +
		"everything. Issue one with `cortex keys issue --client <name> --ttl 90d`, " +
		"or set server.api_keys")

// New builds the server. It fails rather than starting without credentials.
func New(cfg *config.Config, logger ports.Logger) (*Server, error) {
	store, err := NewStore(cfg.Server.DataDir)
	if err != nil {
		return nil, err
	}

	records, err := openRecords(context.Background(), cfg.Server.Database, store)
	if err != nil {
		return nil, err
	}

	issued, err := apikeys.Open(context.Background(), cfg.Server.Database, cfg.Server.DataDir)
	if err != nil {
		records.Close()
		return nil, err
	}

	auth := newAuthenticator(cfg.Server.APIKeys, issued)
	if !auth.configured(context.Background()) {
		issued.Close()
		records.Close()
		return nil, ErrNoAPIKeys
	}

	s := &Server{
		cfg:          cfg,
		store:        store,
		records:      records,
		issued:       issued,
		runner:       NewRunner(cfg, store, records, logger, cfg.Server.Workers),
		auth:         auth,
		logger:       logger,
		mux:          http.NewServeMux(),
		adminClients: adminClients(cfg.Server.AdminClients),
	}
	for name := range s.adminClients {
		// Said out loud at startup: staff access that nobody remembers
		// enabling is the kind that is still enabled two years later.
		logger.Warn("client granted operator access to every tenant's records",
			logField("client", name), logField("source", "server.admin_clients"))
	}
	s.routes()
	return s, nil
}

// Handler returns the authenticated handler tree.
func (s *Server) Handler() http.Handler { return s.middleware(s.mux) }

// Close stops accepting new analyses and releases the key store.
func (s *Server) Close() {
	s.runner.Stop()
	if s.issued != nil {
		s.issued.Close()
	}
	if s.records != nil {
		s.records.Close()
	}
}

// Clients returns how many credentials would work right now, for the startup
// log. Expired ones are not counted: reporting them would overstate access.
func (s *Server) Clients() int { return s.auth.usable(context.Background()) }

func (s *Server) routes() {
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/api/v1/analyses", s.handleAnalyses)
	// Registered before the {id} prefix pattern and more specific than it, so
	// the mux routes /analyses/upload here rather than treating "upload" as an
	// analysis id.
	s.mux.HandleFunc(uploadPath, s.handleUploadAnalysis)
	s.mux.HandleFunc("/api/v1/analyses/", s.handleAnalysisByID)
	s.mux.HandleFunc("/api/v1/scans", s.handleIngestScan)
	s.mux.HandleFunc("/api/v1/projects/", s.handleProjectState)
	s.mux.HandleFunc(webhookPath, s.handleGitHubWebhook)
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
	who, ok := s.callerFrom(w, r)
	if !ok {
		return
	}

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
	name := strings.TrimSpace(req.Project)
	if name == "" {
		// Without a project the analysis has no history to compare against.
		name = projectFromRepository(req.Repository)
	}

	analysis := Analysis{
		ID:    RandomID(),
		Owner: who.name,
		// Scoped here, at the one place a git analysis is born, so the worker
		// that later derives the state path from this field cannot reconcile
		// one client's findings into another's history.
		Project:     projectKey(who.name, name),
		Source:      SourceGit,
		Repository:  req.Repository,
		Ref:         strings.TrimSpace(req.Ref),
		Status:      StatusQueued,
		RequestedBy: who.name,
		QueuedAt:    time.Now().UTC(),
	}

	if err := s.records.SaveAnalysis(r.Context(), analysis); err != nil {
		s.logger.Error("could not queue analysis", logField("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "could not queue the analysis")
		return
	}
	if !s.runner.Enqueue(analysis.ID) {
		analysis.Status = StatusFailed
		analysis.Error = "the queue is full"
		_ = s.records.SaveAnalysis(r.Context(), analysis)
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
	who, ok := s.callerFrom(w, r)
	if !ok {
		return
	}

	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	owner, project := listScope(who, r.URL.Query())
	items, err := s.records.ListAnalyses(r.Context(), owner, project, limit)
	if err != nil {
		// The detail names the database host, user and database on a pgx
		// failure. It goes to the log, not to the caller.
		s.failInternal(w, "could not list the analyses", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"analyses": items,
		"count":    len(items),
	})
}

// listScope decides which records a listing may reach.
//
// A client sees its own and nothing else; ?project= is its own bare name,
// which is scoped here rather than trusted. An operator sees every tenant, may
// narrow to one with ?owner=, and — having no namespace of their own — passes
// the stored key in ?project= when they want a single project, because the
// same name exists once per client.
func listScope(who caller, query url.Values) (owner, project string) {
	owner = who.name
	if who.admin {
		owner = strings.TrimSpace(query.Get("owner"))
	}

	name := strings.TrimSpace(query.Get("project"))
	switch {
	case name == "":
		return owner, ""
	case owner == "":
		return "", name
	default:
		return owner, projectKey(owner, name)
	}
}

// handleAnalysisByID serves /api/v1/analyses/{id} and .../{id}/sarif.
func (s *Server) handleAnalysisByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "read-only endpoint")
		return
	}
	who, ok := s.callerFrom(w, r)
	if !ok {
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

	analysis, found, err := s.records.LoadAnalysis(r.Context(), id)
	if err != nil {
		s.failInternal(w, "could not read the analysis", err)
		return
	}
	// "No such analysis" and "not yours" are deliberately one answer. A 403
	// here would confirm that the id exists and belongs to someone, which is a
	// working oracle for walking another client's analyses — and the SARIF
	// behind them carries their file paths and code snippets. 404 is the house
	// convention for exactly this.
	if !found || !who.canSee(analysis.Owner) {
		writeError(w, http.StatusNotFound, "no analysis with id "+id)
		return
	}

	if !wantSARIF {
		writeJSON(w, http.StatusOK, analysis)
		return
	}

	doc, hasSARIF, readErr := s.records.ReadSARIF(r.Context(), id)
	if readErr != nil {
		s.failInternal(w, "could not read the SARIF document", readErr)
		return
	}
	if !hasSARIF {
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
	who, ok := s.callerFrom(w, r)
	if !ok {
		return
	}

	body, err := readLimited(w, r, 64<<20)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	id := strings.TrimSpace(r.Header.Get("X-Scan-ID"))
	if id == "" {
		id = RandomID()
	}
	id = sanitizeSegment(id)

	// The id comes from the caller, so the document lands in the caller's own
	// namespace. Before this, posting X-Scan-ID: <somebody else's id> replaced
	// their ingested SARIF with whatever this body happened to contain.
	if writeErr := s.store.WriteBlob(s.store.ScanPath(who.name, id), body); writeErr != nil {
		s.failInternal(w, "could not store the document", writeErr)
		return
	}

	s.logger.Info("scan ingested",
		logField("id", id),
		logField("bytes", fmt.Sprint(len(body))),
		logField("client", who.name))

	writeJSON(w, http.StatusCreated, map[string]string{
		"id":  id,
		"url": "/api/v1/scans/" + id,
	})
}

// ---------- project state ----------

// handleProjectState is the server side of the remote state backend: the two
// calls that let a client's CI keep its history here instead of in its repo.
//
// The {project} in the URL stays the client's own bare name — the remote state
// client builds that URL from its configured project, and changing it would
// break every pipeline. What changed is where it lands: the name is resolved
// inside the caller's namespace, so two clients that both call their project
// "api" get two files. There is no cross-tenant case left to answer 403 to;
// asking for somebody else's project simply reads as a project with no history
// yet, which is what a first scan looks like.
func (s *Server) handleProjectState(w http.ResponseWriter, r *http.Request) {
	who, ok := s.callerFrom(w, r)
	if !ok {
		return
	}

	project := projectFromStatePath(r.URL.Path)
	if project == "" {
		writeError(w, http.StatusNotFound, "expected /api/v1/projects/{project}/vulnerabilities")
		return
	}
	path := s.store.ProjectStatePath(projectKey(stateOwner(who, r.URL.Query()), project))

	switch r.Method {
	case http.MethodGet:
		s.readProjectState(w, project, path)
	case http.MethodPut:
		s.writeProjectState(w, r, project, path)
	default:
		writeError(w, http.StatusMethodNotAllowed, "use GET or PUT")
	}
}

// stateOwner is whose namespace the project name is resolved in. A client only
// ever gets its own; an operator may name a tenant with ?owner=, and without
// one falls back to its own rather than to a shared global namespace.
func stateOwner(who caller, query url.Values) string {
	if who.admin {
		if requested := strings.TrimSpace(query.Get("owner")); requested != "" {
			return requested
		}
	}
	return who.name
}

func (s *Server) readProjectState(w http.ResponseWriter, project, path string) {
	doc, found, err := s.store.ReadBlob(path)
	if err != nil {
		// A filesystem error names the data directory. Logged, not returned.
		s.failInternal(w, "could not read the project state", err)
		return
	}
	if !found {
		// No history yet. The client reads this as a first scan.
		writeError(w, http.StatusNotFound, "project "+project+" has no state yet")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(doc)
}

func (s *Server) writeProjectState(
	w http.ResponseWriter, r *http.Request, project, path string,
) {
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
		s.failInternal(w, "could not store the state", writeErr)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"project":         project,
		"vulnerabilities": len(probe.Vulnerabilities),
	})
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

// failInternal answers 500 with a message that says what failed and nothing
// about how.
//
// The handlers used to pass err.Error() straight into the body. With
// server.database set, a pgx failure spells out the database host, user and
// database name; a filesystem failure spells out the data directory. Both went
// to whoever held any valid key. The detail belongs in the operator's log,
// which is where it is now — upload.go:83 and :154 already did this, and this
// is the same pattern with a name.
func (s *Server) failInternal(w http.ResponseWriter, message string, err error) {
	s.logger.Error(message, logField("error", err.Error()))
	writeError(w, http.StatusInternalServerError, message)
}

func logField(key, value string) ports.Field { return ports.F(key, value) }

// RandomID is the identifier scheme analyses and ingested scans share.
func RandomID() string { return bootstrap.RandomIDGen{}.NewScanID().String() }
