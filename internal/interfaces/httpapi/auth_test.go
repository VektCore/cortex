package httpapi_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/infrastructure/apikeys"
	"github.com/vektcore/cortex/internal/infrastructure/config"
	"github.com/vektcore/cortex/internal/infrastructure/logging"
	"github.com/vektcore/cortex/internal/interfaces/httpapi"
)

const day = 24 * time.Hour

// serverWithIssuedKey builds a server whose credentials are issued keys, and
// returns the secret of the one under test.
//
// A second, healthy key always exists: the server refuses to start when no key
// would work at all, so a test about one expired credential needs the server to
// be in the state a real one is — other clients still have access.
func serverWithIssuedKey(
	t *testing.T, issuedAt time.Time, ttl time.Duration, revoke bool,
) (http.Handler, string) {
	t.Helper()

	dir := t.TempDir()
	store, err := apikeys.NewFileStore(dir)
	require.NoError(t, err)

	_, _, err = store.Issue(context.Background(), "other-client", 90*day, time.Now())
	require.NoError(t, err)

	key, secret, err := store.Issue(context.Background(), "acme", ttl, issuedAt)
	require.NoError(t, err)
	if revoke {
		_, err = store.Revoke(context.Background(), key.ID, time.Now())
		require.NoError(t, err)
	}
	store.Close()

	cfg := &config.Config{}
	cfg.Server.DataDir = dir
	cfg.Server.Workers = 1
	cfg.State.Enabled = true

	srv, err := httpapi.New(cfg, logging.NewNop())
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	return srv.Handler(), secret
}

func TestIssuedKey_Authenticates(t *testing.T) {
	t.Parallel()
	h, secret := serverWithIssuedKey(t, time.Now(), 90*day, false)

	rec := do(t, h, http.MethodGet, "/api/v1/analyses", "", secret)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// The client learns when its credential runs out on every response, so an
// expiry arrives as a warning in its own pipeline log rather than as a red
// build on the day it lapses.
func TestIssuedKey_AnnouncesItsExpiry(t *testing.T) {
	t.Parallel()
	h, secret := serverWithIssuedKey(t, time.Now(), 30*day, false)

	rec := do(t, h, http.MethodGet, "/api/v1/analyses", "", secret)

	require.Equal(t, http.StatusOK, rec.Code)
	stamp := rec.Header().Get("X-Cortex-Key-Expires")
	require.NotEmpty(t, stamp)

	expires, err := time.Parse(time.RFC3339, stamp)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(30*day), expires, time.Minute)
}

// The point of a lifetime: it stops working on its own.
func TestExpiredKey_IsRefused(t *testing.T) {
	t.Parallel()
	h, secret := serverWithIssuedKey(t, time.Now().Add(-100*day), 90*day, false)

	rec := do(t, h, http.MethodGet, "/api/v1/analyses", "", secret)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRevokedKey_IsRefused(t *testing.T) {
	t.Parallel()
	h, secret := serverWithIssuedKey(t, time.Now(), 90*day, true)

	rec := do(t, h, http.MethodGet, "/api/v1/analyses", "", secret)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// An expired key that said so would confirm to a stranger that the key was
// once real, and that the client exists. Every refusal reads the same.
func TestRefusals_RevealNothingAboutWhy(t *testing.T) {
	t.Parallel()

	expired, expiredSecret := serverWithIssuedKey(t, time.Now().Add(-100*day), 90*day, false)
	revoked, revokedSecret := serverWithIssuedKey(t, time.Now(), 90*day, true)
	valid, _ := serverWithIssuedKey(t, time.Now(), 90*day, false)

	bodies := []string{
		do(t, expired, http.MethodGet, "/api/v1/analyses", "", expiredSecret).Body.String(),
		do(t, revoked, http.MethodGet, "/api/v1/analyses", "", revokedSecret).Body.String(),
		do(t, valid, http.MethodGet, "/api/v1/analyses", "", "ctx_not-a-real-key").Body.String(),
	}

	for _, body := range bodies {
		assert.Equal(t, bodies[0], body,
			"expired, revoked and unknown must be indistinguishable to the caller")
		assert.NotContains(t, body, "expired")
		assert.NotContains(t, body, "revoked")
		assert.NotContains(t, body, "acme", "a refusal must not confirm the client exists")
	}
}

// An upload is the endpoint that makes this server unpack a stranger's archive.
// It must be behind the same credential as everything else.
func TestUpload_RequiresAValidKeyToo(t *testing.T) {
	t.Parallel()
	h, secret := serverWithIssuedKey(t, time.Now().Add(-100*day), 90*day, false)

	rec := postUpload(t, h, map[string]string{"project": "acme"}, sampleArchive(t), secret)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// A server nobody can authenticate against is refused at startup rather than
// started as something that answers 401 to everything and looks broken.
func TestNew_RefusesWhenEveryKeyHasExpired(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := apikeys.NewFileStore(dir)
	require.NoError(t, err)
	_, _, err = store.Issue(context.Background(), "acme", 1*day, time.Now().Add(-10*day))
	require.NoError(t, err)
	store.Close()

	cfg := &config.Config{}
	cfg.Server.DataDir = dir

	_, err = httpapi.New(cfg, logging.NewNop())

	require.ErrorIs(t, err, httpapi.ErrNoAPIKeys)
}
