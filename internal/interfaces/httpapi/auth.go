package httpapi

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vektcore/cortex/internal/infrastructure/apikeys"
	"github.com/vektcore/cortex/internal/infrastructure/config"
)

// clientNameHeader carries the authenticated client's name to the handlers.
// It is set by the server, never trusted from the request.
const clientNameHeader = "X-Cortex-Client"

// expiryHeader tells an authenticated caller when its credential runs out, on
// every response. A client whose key expires mid-sprint should have seen it
// coming in its own pipeline logs, not discovered it as a red build.
const expiryHeader = "X-Cortex-Key-Expires"

// expiryWarning is how close to the end a key has to be before each use is
// logged as a warning on the server too.
const expiryWarning = 14 * 24 * time.Hour

// authenticator matches a bearer token against two sources.
//
// Issued keys are the real mechanism: one per client, each with an expiry, each
// stored as a hash and revocable without a restart. Static keys from the config
// file are kept because a deployment bootstraps with one — but they never
// expire, which is exactly why they should not be how a client is given access.
type authenticator struct {
	static []config.APIKey
	issued apikeys.Repository
	now    func() time.Time
}

// outcome is the result of checking one token. Reason exists for the server's
// log; the caller only ever sees 401, because telling a stranger that a key is
// "expired" rather than "unknown" confirms the key was real.
type outcome struct {
	client  string
	reason  string
	expires time.Time
	ok      bool
}

func newAuthenticator(keys []config.APIKey, issued apikeys.Repository) *authenticator {
	valid := make([]config.APIKey, 0, len(keys))
	for _, k := range keys {
		if strings.TrimSpace(k.Key) != "" {
			valid = append(valid, k)
		}
	}
	return &authenticator{static: valid, issued: issued, now: time.Now}
}

// configured reports whether anybody can authenticate. A server with no usable
// credential at all is refused at startup rather than started as something that
// answers 401 to every request and looks broken.
func (a *authenticator) configured(ctx context.Context) bool { return a.usable(ctx) > 0 }

// usable counts credentials that would work right now.
func (a *authenticator) usable(ctx context.Context) int {
	n := len(a.static)
	if a.issued != nil {
		n += a.issued.CountUsable(ctx, a.now())
	}
	return n
}

// check resolves a token. Static keys are tried first and in constant time;
// issued keys carry their own constant-time comparison.
func (a *authenticator) check(ctx context.Context, token string) outcome {
	if token == "" {
		return outcome{reason: "missing"}
	}

	if name, matched := a.matchStatic(token); matched {
		return outcome{client: name, ok: true}
	}

	if a.issued == nil {
		return outcome{reason: "unknown"}
	}
	key, status, ok := a.issued.Lookup(ctx, token, a.now())
	if !ok {
		return outcome{client: key.Client, reason: status}
	}
	return outcome{client: key.Client, expires: key.ExpiresAt, ok: true}
}

// matchStatic compares against every configured key even after a match, so
// timing cannot reveal the position of the matching one.
func (a *authenticator) matchStatic(token string) (string, bool) {
	name, matched := "", false
	for _, k := range a.static {
		if subtle.ConstantTimeCompare([]byte(token), []byte(k.Key)) == 1 {
			name, matched = k.Name, true
		}
	}
	if name == "" && matched {
		name = "unnamed"
	}
	return name, matched
}

// middleware rejects anything without a valid key.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Two paths carry their own authentication, or none by design:
		// /healthz because a load balancer cannot hold a credential, and the
		// webhook because GitHub cannot send a bearer token — it signs the
		// body with a shared secret instead, which the handler verifies.
		if r.URL.Path == "/healthz" || r.URL.Path == webhookPath {
			next.ServeHTTP(w, r)
			return
		}

		result := s.auth.check(r.Context(), bearerToken(r))
		if !result.ok {
			// The reason is logged, never returned: an expired key that said
			// so would confirm to a stranger that the key was once real.
			s.logger.Warn("rejected request",
				logField("path", r.URL.Path),
				logField("reason", result.reason),
				logField("client", result.client),
				logField("remote", r.RemoteAddr))
			writeError(w, http.StatusUnauthorized, "invalid or missing API key")
			return
		}

		if !result.expires.IsZero() {
			w.Header().Set(expiryHeader, result.expires.UTC().Format(time.RFC3339))
			s.warnIfExpiring(result)
		}

		r.Header.Set(clientNameHeader, result.client)
		next.ServeHTTP(w, r)
	})
}

// warnIfExpiring puts a key's approaching expiry in the server's log, so the
// operator can rotate it before a client's pipeline starts failing.
func (s *Server) warnIfExpiring(result outcome) {
	remaining := time.Until(result.expires)
	if remaining > expiryWarning {
		return
	}
	s.logger.Warn("API key close to expiry",
		logField("client", result.client),
		logField("expires", result.expires.UTC().Format(time.RFC3339)),
		logField("days_left", strings.TrimSpace(formatDays(remaining))))
}

func formatDays(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days < 0 {
		days = 0
	}
	return strconv.Itoa(days)
}

// bearerToken accepts "Authorization: Bearer <key>" and, for convenience with
// tools that cannot set headers, "?api_key=" is deliberately NOT accepted: a
// key in a URL ends up in access logs and browser history.
func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(header) > len(prefix) && strings.EqualFold(header[:len(prefix)], prefix) {
		return strings.TrimSpace(header[len(prefix):])
	}
	return ""
}
