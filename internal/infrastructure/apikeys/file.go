package apikeys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// fileName is the store's single file, inside the server's data directory so
// it lives on the same mounted volume as everything else that must survive a
// redeploy.
const fileName = "api-keys.json"

// FileStore persists issued keys as one JSON document.
//
// Not a database, for the same reason the analysis store is not: a single
// binary plus a volume has to be the whole deployment, which is what lets the
// engine also run as a step in somebody else's pipeline. The file holds hashes,
// never secrets, but it still says who has access — so it is written 0600 and
// the directory 0700.
type FileStore struct {
	path string
	mu   sync.RWMutex
}

type document struct {
	Keys []Key `json:"keys"`
}

// NewFileStore prepares the store inside dir.
func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("api key dir %q: %w", dir, err)
	}
	return &FileStore{path: filepath.Join(dir, fileName)}, nil
}

// Issue mints a key for a client and returns it with the secret, which is the
// only moment the secret exists in readable form.
func (s *FileStore) Issue(
	_ context.Context, client string, ttl time.Duration, now time.Time,
) (Key, string, error) {
	if client == "" {
		return Key{}, "", ErrNoClient
	}
	if ttl <= 0 {
		return Key{}, "", fmt.Errorf("lifetime must be positive")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	doc, err := s.read()
	if err != nil {
		return Key{}, "", err
	}

	secret, err := NewSecret()
	if err != nil {
		return Key{}, "", err
	}
	id, err := uniqueID(doc.Keys)
	if err != nil {
		return Key{}, "", err
	}

	key := NewKey(id, client, secret, now, ttl)
	doc.Keys = append(doc.Keys, key)
	if writeErr := s.write(doc); writeErr != nil {
		return Key{}, "", writeErr
	}
	return key, secret, nil
}

// Lookup finds the key a secret belongs to, and says why it was refused when
// it was. The reason is for the server's log only: a caller learns nothing
// beyond 401, or an expired key becomes an oracle for guessing valid ones.
func (s *FileStore) Lookup(_ context.Context, secret string, now time.Time) (Key, string, bool) {
	if secret == "" {
		return Key{}, StatusRevoked, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	doc, err := s.read()
	if err != nil {
		return Key{}, "", false
	}

	// Every key is compared even after a match, so the time taken cannot
	// reveal the position of the matching one.
	var found Key
	matched := false
	for _, k := range doc.Keys {
		if k.Matches(secret) {
			found, matched = k, true
		}
	}
	if !matched {
		return Key{}, "unknown", false
	}
	return found, found.Status(now), found.Usable(now)
}

// List returns every key, newest first. Secrets are not in it to return.
func (s *FileStore) List(_ context.Context) ([]Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	doc, err := s.read()
	if err != nil {
		return nil, err
	}
	sort.Slice(doc.Keys, func(i, j int) bool {
		return doc.Keys[i].IssuedAt.After(doc.Keys[j].IssuedAt)
	})
	return doc.Keys, nil
}

// Revoke stops a key working now, without waiting for its expiry. The record
// stays: an audit needs to see that the key existed and when it was withdrawn.
func (s *FileStore) Revoke(_ context.Context, id string, now time.Time) (Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	doc, err := s.read()
	if err != nil {
		return Key{}, err
	}

	for i := range doc.Keys {
		if doc.Keys[i].ID != id {
			continue
		}
		if doc.Keys[i].RevokedAt == nil {
			stamp := now.UTC()
			doc.Keys[i].RevokedAt = &stamp
		}
		if writeErr := s.write(doc); writeErr != nil {
			return Key{}, writeErr
		}
		return doc.Keys[i], nil
	}
	return Key{}, fmt.Errorf("%w: %s", ErrNotFound, id)
}

// CountUsable is what the server reports at startup, and what tells it whether
// anybody can authenticate at all.
func (s *FileStore) CountUsable(_ context.Context, now time.Time) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	doc, err := s.read()
	if err != nil {
		return 0
	}
	n := 0
	for _, k := range doc.Keys {
		if k.Usable(now) {
			n++
		}
	}
	return n
}

// read returns the document, treating absence as empty: a server with no keys
// yet is the normal state before the first one is issued.
func (s *FileStore) read() (document, error) {
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return document{}, nil
	}
	if err != nil {
		return document{}, fmt.Errorf("read api keys: %w", err)
	}

	var doc document
	if unmarshalErr := json.Unmarshal(raw, &doc); unmarshalErr != nil {
		return document{}, fmt.Errorf("parse api keys: %w", unmarshalErr)
	}
	return doc, nil
}

// write replaces the file atomically. A half-written key file is a server that
// will not start, and the rename makes that state unreachable.
func (s *FileStore) write(doc document) error {
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("encode api keys: %w", err)
	}

	tmp := s.path + ".tmp"
	if writeErr := os.WriteFile(tmp, append(encoded, '\n'), 0o600); writeErr != nil {
		return fmt.Errorf("write api keys: %w", writeErr)
	}
	if renameErr := os.Rename(tmp, s.path); renameErr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace api keys: %w", renameErr)
	}
	return nil
}

func uniqueID(existing []Key) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		id, err := randomID()
		if err != nil {
			return "", err
		}

		taken := false
		for _, k := range existing {
			if k.ID == id {
				taken = true
				break
			}
		}
		if !taken {
			return id, nil
		}
	}
	return "", errors.New("could not find a free key id")
}

// Close exists to satisfy Repository. A file store holds nothing to release.
func (s *FileStore) Close() {}

// compile-time proof that the file store is a Repository.
var _ Repository = (*FileStore)(nil)
