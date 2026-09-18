package apikeys_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/infrastructure/apikeys"
)

const day = 24 * time.Hour

func newStore(t *testing.T) (apikeys.Repository, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := apikeys.NewFileStore(dir)
	require.NoError(t, err)
	t.Cleanup(store.Close)
	return store, dir
}

// The secret exists in readable form exactly once. Everything after issue works
// off the hash, so a leaked store hands over nobody's credential.
func TestIssue_ReturnsTheSecretOnceAndStoresOnlyItsHash(t *testing.T) {
	t.Parallel()
	store, dir := newStore(t)
	ctx := context.Background()

	key, secret, err := store.Issue(ctx, "acme", 90*day, time.Now())
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(secret, apikeys.SecretPrefix),
		"the prefix is what makes a leaked key recognisable in a log or a scan")
	assert.NotEmpty(t, key.ID)
	assert.Equal(t, "acme", key.Client)
	assert.NotContains(t, key.Hash, secret)
	assert.Equal(t, secret[len(secret)-4:], key.Hint)

	raw, err := os.ReadFile(filepath.Join(dir, "api-keys.json"))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), secret,
		"the secret must never reach disk")
	assert.Contains(t, string(raw), key.Hash)
}

func TestLookup_MatchesOnlyTheRightSecret(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	_, secret, err := store.Issue(ctx, "acme", 90*day, now)
	require.NoError(t, err)

	found, status, ok := store.Lookup(ctx, secret, now)
	require.True(t, ok)
	assert.Equal(t, "acme", found.Client)
	assert.Equal(t, apikeys.StatusActive, status)

	_, status, ok = store.Lookup(ctx, secret+"x", now)
	assert.False(t, ok)
	assert.Equal(t, "unknown", status)

	_, _, ok = store.Lookup(ctx, "", now)
	assert.False(t, ok)
}

// The whole point of a lifetime: the key stops working on its own, with nobody
// having to remember to remove it.
func TestLookup_RefusesAnExpiredKey(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	issued := time.Now().Add(-100 * day)

	_, secret, err := store.Issue(ctx, "acme", 90*day, issued)
	require.NoError(t, err)

	key, status, ok := store.Lookup(ctx, secret, time.Now())
	assert.False(t, ok)
	assert.Equal(t, apikeys.StatusExpired, status)
	assert.Equal(t, "acme", key.Client,
		"the client is still resolved, so the refusal can be logged against them")
}

func TestRevoke_StopsAKeyImmediately(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	key, secret, err := store.Issue(ctx, "acme", 90*day, now)
	require.NoError(t, err)

	_, _, ok := store.Lookup(ctx, secret, now)
	require.True(t, ok)

	revoked, err := store.Revoke(ctx, key.ID, now)
	require.NoError(t, err)
	require.NotNil(t, revoked.RevokedAt)

	_, status, ok := store.Lookup(ctx, secret, now)
	assert.False(t, ok)
	assert.Equal(t, apikeys.StatusRevoked, status)
}

// When access was withdrawn is the fact an audit needs. A second revoke must
// not overwrite it with a later, misleading timestamp.
func TestRevoke_IsIdempotentAndKeepsTheOriginalTimestamp(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	key, _, err := store.Issue(ctx, "acme", 90*day, now)
	require.NoError(t, err)

	first, err := store.Revoke(ctx, key.ID, now)
	require.NoError(t, err)

	second, err := store.Revoke(ctx, key.ID, now.Add(time.Hour))
	require.NoError(t, err)

	assert.Equal(t, first.RevokedAt.UTC(), second.RevokedAt.UTC())
}

func TestRevoke_UnknownID(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)

	_, err := store.Revoke(context.Background(), "deadbeef", time.Now())

	require.ErrorIs(t, err, apikeys.ErrNotFound)
}

func TestIssue_Validates(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	_, _, err := store.Issue(ctx, "", 90*day, time.Now())
	require.ErrorIs(t, err, apikeys.ErrNoClient)

	_, _, err = store.Issue(ctx, "acme", 0, time.Now())
	require.Error(t, err, "a key with no lifetime is the thing this replaces")
}

// Expired and revoked keys must not be counted: the server reports this number
// at startup, and overstating it would claim access that does not exist.
func TestCountUsable_ExcludesExpiredAndRevoked(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	_, _, err := store.Issue(ctx, "live", 90*day, now)
	require.NoError(t, err)
	_, _, err = store.Issue(ctx, "stale", 1*day, now.Add(-10*day))
	require.NoError(t, err)
	doomed, _, err := store.Issue(ctx, "withdrawn", 90*day, now)
	require.NoError(t, err)
	_, err = store.Revoke(ctx, doomed.ID, now)
	require.NoError(t, err)

	assert.Equal(t, 1, store.CountUsable(ctx, now))
}

func TestList_NewestFirst(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	_, _, err := store.Issue(ctx, "older", 90*day, now.Add(-2*time.Hour))
	require.NoError(t, err)
	_, _, err = store.Issue(ctx, "newer", 90*day, now)
	require.NoError(t, err)

	keys, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, keys, 2)
	assert.Equal(t, "newer", keys[0].Client)
}

// The store is the server's credential list: it has to survive the restart it
// exists for.
func TestFileStore_SurvivesAReopen(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ctx := context.Background()

	first, err := apikeys.NewFileStore(dir)
	require.NoError(t, err)
	_, secret, err := first.Issue(ctx, "acme", 90*day, time.Now())
	require.NoError(t, err)
	first.Close()

	second, err := apikeys.NewFileStore(dir)
	require.NoError(t, err)
	t.Cleanup(second.Close)

	_, _, ok := second.Lookup(ctx, secret, time.Now())
	assert.True(t, ok)
}

func TestFileStore_IsNotWorldReadable(t *testing.T) {
	t.Parallel()

	// Windows has no POSIX permission bits — Go reports 0666 there whatever
	// the file was created with, and access is governed by ACLs instead. The
	// property is real on the platform the server runs on; asserting it on
	// Windows would only be asserting Go's emulation.
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not meaningful on Windows")
	}

	store, dir := newStore(t)

	_, _, err := store.Issue(context.Background(), "acme", 90*day, time.Now())
	require.NoError(t, err)

	info, err := os.Stat(filepath.Join(dir, "api-keys.json"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"the file says who has access, even though it holds no secret")
}

func TestParseTTL(t *testing.T) {
	t.Parallel()

	ok := map[string]time.Duration{
		"90d": 90 * day,
		"1d":  day,
		"12h": 12 * time.Hour,
		"30m": 30 * time.Minute,
		" 7d": 7 * day,
	}
	for in, want := range ok {
		got, err := apikeys.ParseTTL(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}

	for _, in := range []string{"", "0d", "-5d", "forever", "d", "90 days"} {
		_, err := apikeys.ParseTTL(in)
		assert.Error(t, err, "%q must be refused rather than silently misread", in)
	}
}

func TestKeyStatus_RevocationWinsOverExpiry(t *testing.T) {
	t.Parallel()
	now := time.Now()
	revoked := now.Add(-time.Hour)

	key := apikeys.Key{
		ExpiresAt: now.Add(-time.Minute), // already expired
		RevokedAt: &revoked,
	}

	assert.Equal(t, apikeys.StatusRevoked, key.Status(now),
		"revocation is the deliberate act, and the one an audit needs to see")
	assert.False(t, key.Usable(now))
}
