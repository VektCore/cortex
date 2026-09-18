package apikeys

import (
	"context"
	"errors"
	"time"
)

// Errors a caller may want to distinguish.
var (
	// ErrNotFound means no key carries that id.
	ErrNotFound = errors.New("no key with that id")
	// ErrNoClient means a key was issued without saying who for. The client
	// name is what makes a request attributable, so it is not optional.
	ErrNoClient = errors.New("a key must name the client it belongs to")
)

// Repository is where issued keys live.
//
// Two implementations, for two deployments. FileStore keeps the property that
// a single binary plus a volume is the whole service, which is what lets cortex
// also run as a CLI step in somebody else's pipeline. PostgresStore is for the
// server: several instances behind one database, and credentials that can be
// audited with a query rather than by reading JSON off a disk.
type Repository interface {
	// Issue mints a key for a client and returns it with the secret. The
	// secret is returned once and never stored, only its hash.
	Issue(ctx context.Context, client string, ttl time.Duration, now time.Time) (Key, string, error)
	// Lookup resolves a presented secret. The status is for the server's log:
	// telling a caller that a key is "expired" rather than "unknown" confirms
	// the key was once real.
	Lookup(ctx context.Context, secret string, now time.Time) (Key, string, bool)
	// List returns every key, newest first, secrets excluded.
	List(ctx context.Context) ([]Key, error)
	// Revoke stops a key working now. The record stays: an audit has to see
	// that the key existed and when it was withdrawn.
	Revoke(ctx context.Context, id string, now time.Time) (Key, error)
	// CountUsable is how many credentials would authenticate right now.
	CountUsable(ctx context.Context, now time.Time) int
	// Close releases whatever the implementation holds.
	Close()
}

// Open picks the implementation from configuration: a DSN means Postgres, and
// its absence means the file store. One entry point so every caller — the
// server and the keys command — resolves the same way and cannot end up
// issuing keys into a store the server does not read.
func Open(ctx context.Context, dsn, dir string) (Repository, error) {
	if dsn != "" {
		return NewPostgresStore(ctx, dsn)
	}
	return NewFileStore(dir)
}
