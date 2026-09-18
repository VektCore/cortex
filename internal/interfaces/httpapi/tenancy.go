package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

// Tenancy: who owns a record, and which caller may see it.
//
// Per-client API keys used to buy attribution and nothing else. The
// authenticated client name reached the handlers in clientNameHeader, was
// copied into Analysis.RequestedBy and into a log line, and was then never
// consulted again — so any valid key could list, read and overwrite every
// other client's analyses, SARIF and finding history. This file is the missing
// half.
//
// # Where ownership lives
//
// Analysis.Owner, deliberately not Analysis.RequestedBy.
//
// RequestedBy answers "who asked for this run". It is free-text audit trail,
// it is printed in logs, and webhook.go writes the literal "github-webhook"
// into it for a run no API client requested. Owner answers "whose data is
// this", which is an access-control decision, and an access-control decision
// must not share a field with a description: the day somebody makes
// RequestedBy nicer to read ("ci@acme via GitHub Actions") is the day
// authorisation silently starts failing open or closed. For an API-driven
// analysis the two hold the same string today; for a webhook one they do not,
// which is exactly the point.
//
// # Reserved owners
//
// Owners that are not API clients are prefixed with reservedOwnerPrefix. A
// caller that authenticates as a client whose name starts with that prefix is
// refused rather than served: an operator who issued such a key would
// otherwise hand a client the webhook's namespace, and the prefix is the only
// thing keeping internal owners out of the space of names an operator can
// type.
const reservedOwnerPrefix = "cortex:"

// webhookOwner owns analyses queued by the GitHub webhook.
//
// A webhook delivery carries no API key — GitHub signs the body with a shared
// secret instead — so there is no client to attribute the data to. The three
// candidates were: give it to whichever client happens to own a project of the
// same name (a name an attacker picks, so no), leave it unowned (unowned means
// readable by nobody, which is safe but also means the operator cannot see the
// runs they configured), or give it to an owner no API client can ever
// authenticate as. The third is what this is: webhook analyses are visible
// only to a caller with operator access.
//
// The honest limitation: one secret serves every repository, so the server
// cannot tell which client a push belongs to. Mapping repository to owner
// needs configuration (a per-repository secret, or server.webhook_owners) that
// this change cannot add; until then a webhook-driven client reads its results
// through the platform publisher, not through this API.
const webhookOwner = reservedOwnerPrefix + "github-webhook"

// adminClientsEnv names the clients allowed to read every tenant's records.
//
// Staff access exists because the operator runs this server and may
// legitimately have to look at a client's failing analysis. Three properties
// make it safe, and all three are load-bearing:
//
//   - Explicit. The operator names the clients, one per entry, comma
//     separated. There is no wildcard and no "admin" role carried on a key.
//   - Default off. An unset or empty variable is no admin at all, which is
//     what every existing deployment gets.
//   - Not inferrable from a credential. Nothing about issuing, presenting or
//     owning a key grants it; the server matches the authenticated client name
//     against a list it read from its own environment at startup.
//
// It is read from the environment rather than from .cortex.yaml only because
// it is read from server.admin_clients. Viper maps the CORTEX_ prefix with
// dots as underscores, so CORTEX_SERVER_ADMIN_CLIENTS still sets it without a
// config file.
func adminClients(names []string) map[string]struct{} {
	admins := make(map[string]struct{}, len(names))
	for _, name := range names {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			admins[trimmed] = struct{}{}
		}
	}
	if len(admins) == 0 {
		return nil
	}
	return admins
}

// caller is the authenticated identity the handlers authorise against.
type caller struct {
	// name is the client name the authenticator resolved. It is the owner
	// every record this caller creates is stamped with.
	name string
	// admin is operator access: this caller may read records it does not own.
	// It never widens a write — an admin still writes into its own namespace,
	// or into one it names explicitly.
	admin bool
}

// canSee reports whether this caller may read a record owned by owner.
//
// An empty owner is nobody's: records written before ownership existed, and
// rows an older server left behind, are readable only by an operator. Failing
// closed is the only safe direction — the alternative reads "unowned means
// everyone's".
func (c caller) canSee(owner string) bool {
	if c.admin {
		return true
	}
	return owner != "" && owner == c.name
}

// callerFrom resolves the client the auth middleware authenticated.
//
// It writes the response and reports false when the request must not proceed,
// so a handler's first two lines are the whole authorisation preamble.
func (s *Server) callerFrom(w http.ResponseWriter, r *http.Request) (caller, bool) {
	name := strings.TrimSpace(r.Header.Get(clientNameHeader))

	switch {
	case name == "":
		// The middleware always sets a name on a request that got this far, so
		// this is a credential issued without one. Serving it would give it
		// the empty owner, which is the namespace every legacy record sits in.
		s.logger.Error("authenticated request carries no client name",
			logField("path", r.URL.Path))
		writeError(w, http.StatusForbidden,
			"this credential has no client name; ask the operator to reissue it")
		return caller{}, false

	case strings.HasPrefix(name, reservedOwnerPrefix):
		s.logger.Error("refused a client claiming a reserved owner name",
			logField("client", name), logField("path", r.URL.Path))
		writeError(w, http.StatusForbidden,
			"this client name is reserved; ask the operator to reissue the key")
		return caller{}, false
	}

	_, admin := s.adminClients[name]
	return caller{name: name, admin: admin}, true
}

// projectKey is the tenant-scoped identity of a project: "<owner>/<name>".
//
// Project names are chosen by the caller and were global, so "api" was one
// history shared by every client that picked it — an accidental data merge at
// best, and at worst a way to read and rewrite what another client's next
// quality gate calls "new". Scoping the key by owner is what makes two clients
// able to call their project the same thing.
//
// The owner is kept verbatim and the name is sanitised, which is also what
// makes splitProjectKey unambiguous: a sanitised name can never contain "/",
// so the last separator is always the one this function inserted, even for an
// owner whose own name contains slashes.
func projectKey(owner, project string) string {
	return owner + "/" + sanitizeSegment(project)
}

// splitProjectKey takes a key apart again. A key with no separator predates
// scoping and belongs to nobody.
func splitProjectKey(key string) (owner, project string) {
	i := strings.LastIndex(key, "/")
	if i < 0 {
		return "", key
	}
	return key[:i], key[i+1:]
}

// ownerSegment is the directory one client's data lives under.
//
// The sanitised name is there so an operator can still read the data
// directory; the digest of the *raw* name is there because sanitising alone is
// not injective — "acme corp" and "acme/corp" both sanitise to "acme-corp",
// and two clients sharing a directory is precisely the bug this scoping
// exists to prevent. The digest is a disambiguator, not a secret.
func ownerSegment(owner string) string {
	sum := sha256.Sum256([]byte(owner))
	return sanitizeSegment(owner) + "-" + hex.EncodeToString(sum[:4])
}
