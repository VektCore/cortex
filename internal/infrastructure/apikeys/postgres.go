package apikeys

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// schema is applied on connect, and is written to be safe to re-apply. Cortex
// carries its own schema rather than joining VektCore_Migrations: that
// orchestrator runs Alembic out of the service's own image, and a Go binary
// has neither Alembic nor SQLAlchemy in it.
const schema = `
CREATE TABLE IF NOT EXISTS cortex_api_keys (
    id          TEXT PRIMARY KEY,
    client      TEXT NOT NULL,
    hash        TEXT NOT NULL UNIQUE,
    hint        TEXT NOT NULL DEFAULT '',
    issued_at   TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS cortex_api_keys_hash_idx ON cortex_api_keys (hash);
CREATE INDEX IF NOT EXISTS cortex_api_keys_client_idx ON cortex_api_keys (client);
`

// PostgresStore keeps issued keys in a database.
//
// The lookup is by hash, which is what the unique index is on: the secret is
// hashed here and the database only ever sees the digest, so a query log or a
// replica does not leak a credential.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore connects and applies the schema.
func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	if pingErr := pool.Ping(ctx); pingErr != nil {
		pool.Close()
		return nil, fmt.Errorf("reach postgres: %w", pingErr)
	}
	if _, execErr := pool.Exec(ctx, schema); execErr != nil {
		pool.Close()
		return nil, fmt.Errorf("apply api key schema: %w", execErr)
	}
	return &PostgresStore{pool: pool}, nil
}

// Close releases the pool.
func (s *PostgresStore) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// Issue mints a key. The id is retried on collision rather than trusted to be
// unique, because the primary key is what makes `keys revoke` unambiguous.
func (s *PostgresStore) Issue(
	ctx context.Context, client string, ttl time.Duration, now time.Time,
) (Key, string, error) {
	if client == "" {
		return Key{}, "", ErrNoClient
	}
	if ttl <= 0 {
		return Key{}, "", errors.New("lifetime must be positive")
	}

	secret, err := NewSecret()
	if err != nil {
		return Key{}, "", err
	}

	for attempt := 0; attempt < 8; attempt++ {
		id, idErr := randomID()
		if idErr != nil {
			return Key{}, "", idErr
		}
		key := NewKey(id, client, secret, now, ttl)

		_, execErr := s.pool.Exec(ctx, `
			INSERT INTO cortex_api_keys (id, client, hash, hint, issued_at, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			key.ID, key.Client, key.Hash, key.Hint, key.IssuedAt, key.ExpiresAt)
		if execErr == nil {
			return key, secret, nil
		}
		if !isUniqueViolation(execErr) {
			return Key{}, "", fmt.Errorf("store api key: %w", execErr)
		}
	}
	return Key{}, "", errors.New("could not find a free key id")
}

// Lookup resolves a secret by its hash. Unlike the file store there is no scan
// and so no constant-time loop to write: the database is asked for one row by
// an indexed digest, and a miss and a hit cost the same query.
func (s *PostgresStore) Lookup(
	ctx context.Context, secret string, now time.Time,
) (Key, string, bool) {
	if secret == "" {
		return Key{}, "missing", false
	}

	row := s.pool.QueryRow(ctx, `
		SELECT id, client, hash, hint, issued_at, expires_at, revoked_at
		FROM cortex_api_keys WHERE hash = $1`, Fingerprint(secret))

	key, err := scanKey(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Key{}, "unknown", false
	}
	if err != nil {
		return Key{}, "error", false
	}
	return key, key.Status(now), key.Usable(now)
}

// List returns every key, newest first.
func (s *PostgresStore) List(ctx context.Context) ([]Key, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, client, hash, hint, issued_at, expires_at, revoked_at
		FROM cortex_api_keys ORDER BY issued_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	keys := make([]Key, 0, 16)
	for rows.Next() {
		key, scanErr := scanKey(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("read api key: %w", scanErr)
		}
		keys = append(keys, key)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("list api keys: %w", rows.Err())
	}

	sort.SliceStable(keys, func(i, j int) bool {
		return keys[i].IssuedAt.After(keys[j].IssuedAt)
	})
	return keys, nil
}

// Revoke withdraws a key. Revoking an already-revoked key keeps the original
// timestamp: when access was withdrawn is the fact an audit needs, and a second
// call must not overwrite it.
func (s *PostgresStore) Revoke(ctx context.Context, id string, now time.Time) (Key, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE cortex_api_keys
		SET revoked_at = COALESCE(revoked_at, $2)
		WHERE id = $1
		RETURNING id, client, hash, hint, issued_at, expires_at, revoked_at`,
		id, now.UTC())

	key, err := scanKey(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Key{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return Key{}, fmt.Errorf("revoke api key: %w", err)
	}
	return key, nil
}

// CountUsable counts credentials that would authenticate right now.
func (s *PostgresStore) CountUsable(ctx context.Context, now time.Time) int {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM cortex_api_keys
		WHERE revoked_at IS NULL AND expires_at > $1`, now.UTC()).Scan(&n)
	if err != nil {
		return 0
	}
	return n
}

// scanRow is what both QueryRow and Rows satisfy, so one scanner serves both.
type scanRow interface {
	Scan(dest ...any) error
}

func scanKey(row scanRow) (Key, error) {
	var key Key
	var revoked *time.Time
	if err := row.Scan(&key.ID, &key.Client, &key.Hash, &key.Hint,
		&key.IssuedAt, &key.ExpiresAt, &revoked); err != nil {
		return Key{}, err
	}
	key.RevokedAt = revoked
	return key, nil
}

// isUniqueViolation reports whether the error is SQLSTATE 23505, which is the
// only insert failure worth retrying with a fresh id.
func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	return errors.As(err, &pgErr) && pgErr.SQLState() == "23505"
}

// compile-time proof that the postgres store is a Repository.
var _ Repository = (*PostgresStore)(nil)
