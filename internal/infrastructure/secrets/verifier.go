// Package secrets checks whether a leaked credential still works.
//
// A secret scanner reports pattern matches. That answers "is there a token in
// this file", not "is there an incident". A token rotated three months ago is
// hygiene debt; a live one is an attacker's way in, right now. Ranking them the
// same is why secret findings get ignored in bulk.
//
// # What this does to the credential
//
// Verification sends the credential to the provider it belongs to, in a
// read-only call ("whose token is this?"). That is a deliberate trade: the
// secret is already leaked, and the provider is its owner. It still means the
// value leaves the machine, so this is opt-in per scanner
// (scanners.gitleaks.options.verify) and never on by default.
//
// Nothing is logged: not the secret, not a prefix of it.
package secrets

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// Validity is the outcome of a check.
type Validity int

const (
	// ValidityUnknown means no provider recognised the credential, the network
	// failed, or the provider answered something unexpected. Never treated as
	// "safe".
	ValidityUnknown Validity = iota
	// ValidityLive means the provider accepted the credential.
	ValidityLive
	// ValidityRevoked means the provider rejected it: rotated, expired, or
	// never real. Still a finding — it is in the history — just not an
	// incident.
	ValidityRevoked
)

// String returns the canonical lowercase representation.
func (v Validity) String() string {
	switch v {
	case ValidityLive:
		return "live"
	case ValidityRevoked:
		return "revoked"
	case ValidityUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// provider knows how to ask one service whether a credential is still good.
type provider struct {
	// name is used in the finding message.
	name string
	// matches decides whether a Gitleaks rule id belongs to this provider.
	matches func(ruleID string) bool
	// request builds the read-only probe.
	request func(ctx context.Context, secret string) (*http.Request, error)
	// live interprets the response status. Anything else is unknown, so a rate
	// limit or an outage never reads as "revoked".
	live    []int
	revoked []int
}

// Verifier checks credentials against their providers.
type Verifier struct {
	client    *http.Client
	providers []provider
}

// New returns a Verifier with a short timeout: a scan cannot wait on a slow
// third party, and an unanswered probe is simply "unknown".
func New(timeout time.Duration) *Verifier {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Verifier{
		client:    &http.Client{Timeout: timeout},
		providers: builtinProviders(),
	}
}

// Verify reports whether the credential still works. ruleID is the Gitleaks
// rule that found it, which is how the provider is identified.
func (v *Verifier) Verify(ctx context.Context, ruleID, secret string) (Validity, string) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return ValidityUnknown, ""
	}

	for _, p := range v.providers {
		if !p.matches(strings.ToLower(ruleID)) {
			continue
		}

		req, err := p.request(ctx, secret)
		if err != nil {
			return ValidityUnknown, p.name
		}

		resp, err := v.client.Do(req)
		if err != nil {
			return ValidityUnknown, p.name
		}
		_ = resp.Body.Close()

		if contains(p.live, resp.StatusCode) {
			return ValidityLive, p.name
		}
		if contains(p.revoked, resp.StatusCode) {
			return ValidityRevoked, p.name
		}
		return ValidityUnknown, p.name
	}
	return ValidityUnknown, ""
}

// Supports reports whether any provider can check this rule, so callers can
// skip the ones nobody can verify.
func (v *Verifier) Supports(ruleID string) bool {
	lower := strings.ToLower(ruleID)
	for _, p := range v.providers {
		if p.matches(lower) {
			return true
		}
	}
	return false
}

func builtinProviders() []provider {
	return []provider{
		{
			name:    "GitHub",
			matches: ruleContains("github"),
			request: bearerRequest("https://api.github.com/user"),
			live:    []int{http.StatusOK},
			revoked: []int{http.StatusUnauthorized},
		},
		{
			name:    "Stripe",
			matches: ruleContains("stripe"),
			request: bearerRequest("https://api.stripe.com/v1/account"),
			live:    []int{http.StatusOK},
			revoked: []int{http.StatusUnauthorized},
		},
		{
			name:    "OpenAI",
			matches: ruleContains("openai"),
			request: bearerRequest("https://api.openai.com/v1/models"),
			live:    []int{http.StatusOK},
			revoked: []int{http.StatusUnauthorized},
		},
		{
			name:    "Slack",
			matches: ruleContains("slack"),
			request: bearerRequest("https://slack.com/api/auth.test"),
			// Slack answers 200 with {"ok": false} for a dead token, so a 200
			// alone cannot mean live. Left as unknown rather than guessed.
			live:    nil,
			revoked: []int{http.StatusUnauthorized},
		},
		{
			name:    "SendGrid",
			matches: ruleContains("sendgrid"),
			request: bearerRequest("https://api.sendgrid.com/v3/scopes"),
			live:    []int{http.StatusOK},
			revoked: []int{http.StatusUnauthorized, http.StatusForbidden},
		},
	}
}

// ruleContains matches a Gitleaks rule id by substring: its ids are
// provider-prefixed ("github-pat", "stripe-access-token").
func ruleContains(needle string) func(string) bool {
	return func(ruleID string) bool { return strings.Contains(ruleID, needle) }
}

// bearerRequest builds a GET carrying the credential as a bearer token, which
// is what all the providers above accept.
func bearerRequest(url string) func(context.Context, string) (*http.Request, error) {
	return func(ctx context.Context, secret string) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("User-Agent", "cortex-secret-verification")
		return req, nil
	}
}

func contains(codes []int, code int) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}
