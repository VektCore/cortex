package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	gitinfra "github.com/vektcore/cortex/internal/infrastructure/git"
)

// webhookPath is excluded from bearer-key auth: the signature is the credential.
const webhookPath = "/api/v1/webhooks/github"

// GitHub webhook headers.
const (
	headerEvent     = "X-GitHub-Event"
	headerSignature = "X-Hub-Signature-256"
	headerDelivery  = "X-GitHub-Delivery"
)

// pushEvent is the slice of GitHub's push payload Cortex needs. The payload is
// large and mostly irrelevant: what matters is which repository moved, to what
// branch, and whether the branch was deleted.
type pushEvent struct {
	Ref        string `json:"ref"` // refs/heads/master
	Deleted    bool   `json:"deleted"`
	Repository struct {
		FullName string `json:"full_name"` // org/repo
		CloneURL string `json:"clone_url"`
		SSHURL   string `json:"ssh_url"`
		Private  bool   `json:"private"`
		Default  string `json:"default_branch"`
	} `json:"repository"`
	HeadCommit *struct {
		ID string `json:"id"`
	} `json:"head_commit"`
}

// handleGitHubWebhook queues an analysis when a repository is pushed.
//
// This is what makes "connect a repository" mean pasting a URL into the repo's
// settings: nothing is installed, no workflow is added, and the scan runs here
// rather than on the client's runner.
//
// Authentication is GitHub's HMAC signature over the body, not the API key —
// GitHub cannot send a bearer token, and a shared secret per repository is what
// it does offer.
func (s *Server) handleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}

	body, err := readLimited(w, r, 8<<20)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !s.validSignature(body, r.Header.Get(headerSignature)) {
		s.logger.Warn("webhook rejected: bad signature",
			logField("delivery", r.Header.Get(headerDelivery)))
		writeError(w, http.StatusUnauthorized, "invalid signature")
		return
	}

	event := r.Header.Get(headerEvent)
	if event == "ping" {
		writeJSON(w, http.StatusOK, map[string]string{"status": "pong"})
		return
	}
	if event != "push" {
		// Acknowledged and ignored: a repository may be sending every event.
		writeJSON(w, http.StatusOK, map[string]string{"ignored": event})
		return
	}

	s.queuePush(w, r, body)
}

// queuePush turns a verified push payload into a queued analysis. Split from
// the handler so neither half has to hold both the transport concerns and the
// decision of what is worth scanning.
func (s *Server) queuePush(w http.ResponseWriter, r *http.Request, body []byte) {
	var push pushEvent
	if err := json.Unmarshal(body, &push); err != nil {
		writeError(w, http.StatusBadRequest, "push payload is not JSON")
		return
	}

	branch := strings.TrimPrefix(push.Ref, "refs/heads/")
	if push.Deleted {
		writeJSON(w, http.StatusOK, map[string]string{"ignored": "branch deleted"})
		return
	}
	if branch == "" || push.Repository.FullName == "" {
		writeError(w, http.StatusBadRequest, "push payload names no branch or repository")
		return
	}
	if !s.watchedBranch(branch, push.Repository.Default) {
		// Feature branches would multiply the work without changing the number
		// anybody looks at. Only the branch of record is analysed.
		writeJSON(w, http.StatusOK, map[string]string{"ignored": "branch " + branch})
		return
	}

	analysis := Analysis{
		ID:          RandomID(),
		Project:     sanitizeSegment(strings.ReplaceAll(push.Repository.FullName, "/", "-")),
		Repository:  cloneURLFor(push, gitinfra.HasToken()),
		Ref:         branch,
		Status:      StatusQueued,
		RequestedBy: "github-webhook",
		QueuedAt:    time.Now().UTC(),
	}

	if err := s.store.SaveAnalysis(analysis); err != nil {
		writeError(w, http.StatusInternalServerError, "could not queue the analysis")
		return
	}
	if !s.runner.Enqueue(analysis.ID) {
		writeError(w, http.StatusServiceUnavailable, "the queue is full; GitHub will retry")
		return
	}

	s.logger.Info("analysis queued from webhook",
		logField("id", analysis.ID),
		logField("repository", push.Repository.FullName),
		logField("branch", branch),
		logField("delivery", r.Header.Get(headerDelivery)))

	writeJSON(w, http.StatusAccepted, map[string]string{
		"id":      analysis.ID,
		"project": analysis.Project,
		"branch":  branch,
		"url":     "/api/v1/analyses/" + analysis.ID,
	})
}

// validSignature checks GitHub's HMAC-SHA256 over the raw body.
//
// With no secret configured the endpoint is closed rather than open: an
// unauthenticated webhook lets anyone on the internet make this server clone
// repositories on demand.
func (s *Server) validSignature(body []byte, header string) bool {
	secret := s.cfg.Server.WebhookSecret
	if secret == "" {
		return false
	}

	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	want, err := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return hmac.Equal(mac.Sum(nil), want)
}

// watchedBranch reports whether a push to this branch is worth analysing.
func (s *Server) watchedBranch(branch, repoDefault string) bool {
	configured := s.cfg.Server.WebhookBranches
	if len(configured) == 0 {
		// No list: follow whatever the repository calls its default branch,
		// plus the two names that are almost always it.
		return branch == repoDefault || branch == "main" || branch == "master"
	}
	for _, candidate := range configured {
		if branch == strings.TrimSpace(candidate) {
			return true
		}
	}
	return false
}

// cloneURLFor picks how to reach the repository.
//
// A public repository needs no credential, so HTTPS. A private one needs
// whichever the server actually has: HTTPS when a token is configured — one
// token covers every repository it can read — and SSH otherwise, which means a
// deploy key per repository. Choosing SSH unconditionally would force key
// management on an operator who already has a token.
func cloneURLFor(push pushEvent, hasToken bool) string {
	if push.Repository.Private && !hasToken && push.Repository.SSHURL != "" {
		return push.Repository.SSHURL
	}
	if push.Repository.CloneURL != "" {
		return push.Repository.CloneURL
	}
	return "github.com/" + push.Repository.FullName
}
