package httpapi

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/vektcore/cortex/internal/infrastructure/config"
)

// clientNameHeader carries the authenticated client's name to the handlers.
// It is set by the server, never trusted from the request.
const clientNameHeader = "X-Cortex-Client"

// authenticator matches a bearer token against the configured keys.
//
// Comparison is constant-time and the key itself is never logged or echoed: an
// error says "invalid credentials", not which key was close.
type authenticator struct {
	keys []config.APIKey
}

func newAuthenticator(keys []config.APIKey) *authenticator {
	valid := make([]config.APIKey, 0, len(keys))
	for _, k := range keys {
		if strings.TrimSpace(k.Key) != "" {
			valid = append(valid, k)
		}
	}
	return &authenticator{keys: valid}
}

// configured reports whether any usable key exists. A server with none would
// accept everything, so it refuses to start instead.
func (a *authenticator) configured() bool { return len(a.keys) > 0 }

// clientFor returns the name behind a token, and whether it matched.
func (a *authenticator) clientFor(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	// Every key is compared even after a match, so timing cannot reveal the
	// position of the matching key.
	name, matched := "", false
	for _, k := range a.keys {
		if subtle.ConstantTimeCompare([]byte(token), []byte(k.Key)) == 1 {
			name, matched = k.Name, true
		}
	}
	if name == "" && matched {
		name = "unnamed"
	}
	return name, matched
}

// middleware rejects anything without a valid key, except the health endpoint:
// a load balancer cannot be expected to hold a credential.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		client, ok := s.auth.clientFor(bearerToken(r))
		if !ok {
			s.logger.Warn("rejected request",
				logField("path", r.URL.Path),
				logField("remote", r.RemoteAddr))
			writeError(w, http.StatusUnauthorized, "invalid or missing API key")
			return
		}

		r.Header.Set(clientNameHeader, client)
		next.ServeHTTP(w, r)
	})
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
