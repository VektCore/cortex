// Package apikeys issues and verifies the credentials clients authenticate
// with, each belonging to one client and each with an expiry.
//
// Two properties drive the design. The secret is never stored — only its
// SHA-256 — so a leaked data directory does not hand over every client's
// credential, and a key that is lost cannot be recovered, only replaced. And
// every key expires: a credential that lets a stranger upload archives for this
// server to unpack and scan should stop working on its own, rather than living
// until somebody remembers to remove it from a YAML file.
//
// SHA-256 rather than bcrypt or argon2 is deliberate. Those exist to make
// guessing a low-entropy human password expensive. These secrets are 32 bytes
// from crypto/rand, so there is nothing to guess and a slow hash would only
// make every request slower.
package apikeys

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SecretPrefix marks a Cortex credential wherever it turns up — a log, a CI
// variable, a pasted snippet — and gives secret scanners something to match.
const SecretPrefix = "ctx_"

// secretBytes is the entropy behind one key.
const secretBytes = 32

// Status values a key can be in.
const (
	StatusActive  = "active"
	StatusExpired = "expired"
	StatusRevoked = "revoked"
)

// Key is one issued credential as it is stored: everything needed to recognise
// and audit a secret, but not the secret.
type Key struct {
	// ID names the key in `keys list` and `keys revoke`. It is public.
	ID string `json:"id"`
	// Client is who the key belongs to. It appears in the logs and on every
	// analysis, so work is attributable without printing a credential.
	Client string `json:"client"`
	// Hash is the SHA-256 of the secret, hex-encoded.
	Hash string `json:"hash"`
	// Hint is the last four characters of the secret, so an operator can tell
	// two of a client's keys apart during a rotation without revealing either.
	Hint      string     `json:"hint"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// Status reports what the key is at a point in time. Revocation wins over
// expiry: it is the deliberate act, and the one worth seeing in an audit.
func (k Key) Status(now time.Time) string {
	switch {
	case k.RevokedAt != nil:
		return StatusRevoked
	case !now.Before(k.ExpiresAt):
		return StatusExpired
	default:
		return StatusActive
	}
}

// Usable reports whether the key may authenticate a request now.
func (k Key) Usable(now time.Time) bool { return k.Status(now) == StatusActive }

// Matches compares a presented secret against this key in constant time, so a
// near-miss cannot be distinguished from a wrong guess by how long it took.
func (k Key) Matches(secret string) bool {
	presented := Fingerprint(secret)
	return subtle.ConstantTimeCompare([]byte(presented), []byte(k.Hash)) == 1
}

// Fingerprint is the stored form of a secret.
func Fingerprint(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// NewSecret mints a credential. The returned string is the only time it exists
// in readable form; the caller shows it once and stores the Key.
func NewSecret() (string, error) {
	raw := make([]byte, secretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return SecretPrefix + hex.EncodeToString(raw), nil
}

// NewKey builds the record for a freshly minted secret.
func NewKey(id, client, secret string, now time.Time, ttl time.Duration) Key {
	return Key{
		ID:        id,
		Client:    client,
		Hash:      Fingerprint(secret),
		Hint:      hint(secret),
		IssuedAt:  now.UTC(),
		ExpiresAt: now.UTC().Add(ttl),
	}
}

func hint(secret string) string {
	if len(secret) < 4 {
		return ""
	}
	return secret[len(secret)-4:]
}

// ParseTTL accepts what an operator would actually type. Go's own parser stops
// at hours, and "90d" is how anybody describes the lifetime of a credential.
func ParseTTL(raw string) (time.Duration, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, fmt.Errorf("empty lifetime")
	}

	if days, ok := strings.CutSuffix(trimmed, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil {
			return 0, fmt.Errorf("invalid lifetime %q: %w", raw, err)
		}
		if n <= 0 {
			return 0, fmt.Errorf("lifetime %q must be positive", raw)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}

	d, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, fmt.Errorf("invalid lifetime %q: use 90d, 12h or 30m", raw)
	}
	if d <= 0 {
		return 0, fmt.Errorf("lifetime %q must be positive", raw)
	}
	return d, nil
}

// randomID mints the short public identifier a key is named by in `keys list`
// and `keys revoke`. Four bytes is plenty: ids are scoped to one deployment's
// key table, and collisions are retried by the caller rather than assumed away.
func randomID() (string, error) {
	raw := make([]byte, 4)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate key id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}
