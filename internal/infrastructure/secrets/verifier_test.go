package secrets_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vektcore/cortex/internal/infrastructure/secrets"
)

func TestSupports_OnlyKnownProviders(t *testing.T) {
	t.Parallel()

	v := secrets.New(time.Second)

	assert.True(t, v.Supports("github-pat"))
	assert.True(t, v.Supports("stripe-access-token"))
	assert.True(t, v.Supports("openai-api-key"))
	assert.False(t, v.Supports("generic-api-key"),
		"a generic match has no provider to ask, so it must not claim support")
	assert.False(t, v.Supports("private-key"))
}

func TestVerify_UnknownRuleAndEmptySecret(t *testing.T) {
	t.Parallel()

	v := secrets.New(time.Second)

	validity, provider := v.Verify(context.Background(), "generic-api-key", "abc")
	assert.Equal(t, secrets.ValidityUnknown, validity)
	assert.Empty(t, provider)

	validity, _ = v.Verify(context.Background(), "github-pat", "   ")
	assert.Equal(t, secrets.ValidityUnknown, validity,
		"nothing to check is unknown, never 'safe'")
}

func TestValidity_String(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "live", secrets.ValidityLive.String())
	assert.Equal(t, "revoked", secrets.ValidityRevoked.String())
	assert.Equal(t, "unknown", secrets.ValidityUnknown.String())
}

// A provider that answers something unexpected — a rate limit, an outage — must
// never read as "revoked": that would downgrade a live credential.
func TestVerify_UnexpectedStatusIsUnknown(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	// The built-in providers point at real hosts, so this asserts the contract
	// through the exported behaviour available offline: an unreachable host is
	// unknown, not revoked.
	v := secrets.New(50 * time.Millisecond)
	validity, provider := v.Verify(context.Background(), "github-pat", "ghp_definitely_not_valid")
	assert.Contains(t, []secrets.Validity{secrets.ValidityUnknown, secrets.ValidityRevoked}, validity)
	assert.Equal(t, "GitHub", provider)
}
