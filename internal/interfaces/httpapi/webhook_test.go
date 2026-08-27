package httpapi_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/infrastructure/config"
	"github.com/vektcore/cortex/internal/infrastructure/logging"
	"github.com/vektcore/cortex/internal/interfaces/httpapi"
)

const webhookSecret = "s3cr3t-webhook"

func newWebhookServer(t *testing.T, branches ...string) http.Handler {
	t.Helper()

	cfg := &config.Config{}
	cfg.Server.DataDir = t.TempDir()
	cfg.Server.Workers = 1
	cfg.Server.APIKeys = []config.APIKey{{Name: "test-client", Key: testKey}}
	cfg.Server.WebhookSecret = webhookSecret
	cfg.Server.WebhookBranches = branches

	srv, err := httpapi.New(cfg, logging.NewNop())
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	return srv.Handler()
}

// sign reproduces what GitHub does to every delivery.
func sign(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func deliver(t *testing.T, h http.Handler, event, body, signature string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-GitHub-Delivery", "test-delivery")
	if signature != "" {
		req.Header.Set("X-Hub-Signature-256", signature)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func pushBody(branch, fullName string, private bool) string {
	payload := map[string]any{
		"ref": "refs/heads/" + branch,
		"repository": map[string]any{
			"full_name":      fullName,
			"clone_url":      "https://github.com/" + fullName + ".git",
			"ssh_url":        "git@github.com:" + fullName + ".git",
			"private":        private,
			"default_branch": "master",
		},
	}
	encoded, _ := json.Marshal(payload)
	return string(encoded)
}

// The signature is the credential here. Without it, anyone who finds the URL
// could make this server clone repositories on demand.
func TestWebhook_RejectsAnUnsignedDelivery(t *testing.T) {
	t.Parallel()
	h := newWebhookServer(t)

	rec := deliver(t, h, "push", pushBody("master", "acme/api", false), "")

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestWebhook_RejectsAForgedSignature(t *testing.T) {
	t.Parallel()
	h := newWebhookServer(t)

	body := pushBody("master", "acme/api", false)
	rec := deliver(t, h, "push", body, sign("the-wrong-secret", body))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// A body altered after signing must not pass: the MAC covers the payload, not
// just the fact that someone knew the secret once.
func TestWebhook_RejectsATamperedBody(t *testing.T) {
	t.Parallel()
	h := newWebhookServer(t)

	signed := pushBody("master", "acme/api", false)
	tampered := pushBody("master", "attacker/evil", false)

	rec := deliver(t, h, "push", tampered, sign(webhookSecret, signed))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestWebhook_QueuesAnalysisOnPush(t *testing.T) {
	t.Parallel()
	h := newWebhookServer(t)

	body := pushBody("master", "punixxher/financeApp", false)
	rec := deliver(t, h, "push", body, sign(webhookSecret, body))

	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())

	var got map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.NotEmpty(t, got["id"])
	assert.Equal(t, "master", got["branch"])
	assert.Equal(t, "punixxher-financeApp", got["project"],
		"one repository is one project, whatever triggered the analysis")
}

// GitHub sends a ping when the webhook is created; answering it is how the
// setup page turns green.
func TestWebhook_AnswersPing(t *testing.T) {
	t.Parallel()
	h := newWebhookServer(t)

	body := `{"zen":"Design for failure."}`
	rec := deliver(t, h, "ping", body, sign(webhookSecret, body))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "pong")
}

// Analysing every feature branch would multiply the work without changing the
// number anybody looks at.
func TestWebhook_IgnoresOtherBranches(t *testing.T) {
	t.Parallel()
	h := newWebhookServer(t)

	body := pushBody("feature/login", "acme/api", false)
	rec := deliver(t, h, "push", body, sign(webhookSecret, body))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ignored")
}

func TestWebhook_HonoursTheConfiguredBranchList(t *testing.T) {
	t.Parallel()
	h := newWebhookServer(t, "develop")

	accepted := pushBody("develop", "acme/api", false)
	rec := deliver(t, h, "push", accepted, sign(webhookSecret, accepted))
	assert.Equal(t, http.StatusAccepted, rec.Code)

	ignored := pushBody("master", "acme/api", false)
	rec = deliver(t, h, "push", ignored, sign(webhookSecret, ignored))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ignored")
}

// A deleted branch has nothing to scan.
func TestWebhook_IgnoresBranchDeletion(t *testing.T) {
	t.Parallel()
	h := newWebhookServer(t)

	body := `{"ref":"refs/heads/master","deleted":true,` +
		`"repository":{"full_name":"acme/api","default_branch":"master"}}`
	rec := deliver(t, h, "push", body, sign(webhookSecret, body))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "deleted")
}

// With no secret configured the endpoint stays closed rather than open.
func TestWebhook_ClosedWhenNoSecretIsConfigured(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	cfg.Server.DataDir = t.TempDir()
	cfg.Server.Workers = 1
	cfg.Server.APIKeys = []config.APIKey{{Name: "c", Key: testKey}}
	// No WebhookSecret.

	srv, err := httpapi.New(cfg, logging.NewNop())
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	body := pushBody("master", "acme/api", false)
	rec := deliver(t, srv.Handler(), "push", body, sign("anything", body))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// A private repository is cloned over SSH, where a deploy key is the usual
// arrangement; a public one over HTTPS.
func TestWebhook_PrivateRepositoryIsClonedOverSSH(t *testing.T) {
	t.Parallel()
	h := newWebhookServer(t)

	body := pushBody("master", "acme/private-api", true)
	rec := deliver(t, h, "push", body, sign(webhookSecret, body))
	require.Equal(t, http.StatusAccepted, rec.Code)

	var queued map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &queued))

	stored := do(t, h, http.MethodGet, "/api/v1/analyses/"+queued["id"], "", testKey)
	require.Equal(t, http.StatusOK, stored.Code)

	var analysis httpapi.Analysis
	require.NoError(t, json.Unmarshal(stored.Body.Bytes(), &analysis))
	assert.Equal(t, "git@github.com:acme/private-api.git", analysis.Repository)
}
