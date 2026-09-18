//go:build integration

package apikeys_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/infrastructure/apikeys"
)

// newPostgres skips rather than fails when there is no database: the unit
// suite has to stay runnable on a laptop with nothing installed.
func newPostgres(t *testing.T) apikeys.Repository {
	t.Helper()

	dsn := os.Getenv("CORTEX_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set CORTEX_TEST_POSTGRES_DSN to run the postgres tests")
	}

	ctx := context.Background()
	store, err := apikeys.NewPostgresStore(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(store.Close)
	return store
}

// The schema is applied on every connect, so a second server starting against
// the same database must not fail on tables that already exist.
func TestPostgres_SchemaIsReapplicable(t *testing.T) {
	first := newPostgres(t)
	require.NotNil(t, first)

	second := newPostgres(t)
	assert.NotNil(t, second)
}

func TestPostgres_IssueLookupRevoke(t *testing.T) {
	store := newPostgres(t)
	ctx := context.Background()
	now := time.Now()

	key, secret, err := store.Issue(ctx, "acme-pg", 90*day, now)
	require.NoError(t, err)

	found, status, ok := store.Lookup(ctx, secret, now)
	require.True(t, ok)
	assert.Equal(t, "acme-pg", found.Client)
	assert.Equal(t, apikeys.StatusActive, status)
	assert.Equal(t, key.ID, found.ID)

	_, status, ok = store.Lookup(ctx, secret+"x", now)
	assert.False(t, ok)
	assert.Equal(t, "unknown", status)

	revoked, err := store.Revoke(ctx, key.ID, now)
	require.NoError(t, err)
	require.NotNil(t, revoked.RevokedAt)

	_, status, ok = store.Lookup(ctx, secret, now)
	assert.False(t, ok)
	assert.Equal(t, apikeys.StatusRevoked, status)
}

// COALESCE, not an unconditional assignment: a second revoke must not move the
// timestamp an audit relies on.
func TestPostgres_RevokeKeepsTheOriginalTimestamp(t *testing.T) {
	store := newPostgres(t)
	ctx := context.Background()
	now := time.Now()

	key, _, err := store.Issue(ctx, "acme-pg", 90*day, now)
	require.NoError(t, err)

	first, err := store.Revoke(ctx, key.ID, now)
	require.NoError(t, err)
	second, err := store.Revoke(ctx, key.ID, now.Add(time.Hour))
	require.NoError(t, err)

	assert.Equal(t, first.RevokedAt.UTC(), second.RevokedAt.UTC())
}

func TestPostgres_ExpiryIsEnforcedInTheQuery(t *testing.T) {
	store := newPostgres(t)
	ctx := context.Background()
	now := time.Now()

	_, secret, err := store.Issue(ctx, "stale-pg", 1*day, now.Add(-10*day))
	require.NoError(t, err)

	_, status, ok := store.Lookup(ctx, secret, now)
	assert.False(t, ok)
	assert.Equal(t, apikeys.StatusExpired, status)
}

func TestPostgres_CountUsableAndList(t *testing.T) {
	store := newPostgres(t)
	ctx := context.Background()
	now := time.Now()

	before := store.CountUsable(ctx, now)

	_, _, err := store.Issue(ctx, "counted-pg", 90*day, now)
	require.NoError(t, err)

	assert.Equal(t, before+1, store.CountUsable(ctx, now))

	keys, err := store.List(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, keys)
	for i := 1; i < len(keys); i++ {
		assert.False(t, keys[i].IssuedAt.After(keys[i-1].IssuedAt),
			"list must come back newest first")
	}
}

func TestPostgres_RevokeUnknownID(t *testing.T) {
	store := newPostgres(t)

	_, err := store.Revoke(context.Background(), "nosuchid", time.Now())

	require.ErrorIs(t, err, apikeys.ErrNotFound)
}
