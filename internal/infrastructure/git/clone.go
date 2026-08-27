package git

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

// TokenEnvVars are read, in order, for a credential to inject into an HTTPS
// clone URL. GITHUB_TOKEN is the name GitHub Actions already exports.
var TokenEnvVars = []string{"CORTEX_GIT_TOKEN", "GITHUB_TOKEN", "GITLAB_TOKEN"}

// CloneSpec describes a repository to fetch for analysis.
type CloneSpec struct {
	// URL is any form git understands: https://host/org/repo(.git),
	// git@host:org/repo.git, or a bare host/org/repo (https is assumed).
	URL string
	// Ref is a branch, tag or commit. Empty means the default branch.
	Ref string
	// Full requests the whole history instead of a depth-1 clone. Needed only
	// when scanning commit history (gitleaks git).
	Full bool
}

// Clone fetches a repository into a temporary directory and returns its path
// plus a cleanup that removes it. The cleanup is always safe to call.
//
// Credentials come from the ambient environment: an SSH agent for scp-style
// URLs, or one of TokenEnvVars for HTTPS. The token is injected into the URL
// passed to git and never logged.
func Clone(ctx context.Context, spec CloneSpec) (string, func(), error) {
	noop := func() {}

	if strings.TrimSpace(spec.URL) == "" {
		return "", noop, fmt.Errorf("git clone: empty URL")
	}

	dir, err := os.MkdirTemp("", "cortex-clone-*")
	if err != nil {
		return "", noop, fmt.Errorf("git clone: create temp dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	args := []string{"clone", "--quiet"}
	if !spec.Full {
		args = append(args, "--depth", "1")
	}
	if spec.Ref != "" {
		// --branch takes a branch or tag. A raw commit SHA needs a full clone
		// plus a checkout, handled below.
		args = append(args, "--branch", spec.Ref)
	}
	args = append(args, withCredentials(NormalizeURL(spec.URL)), dir)

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, runErr := cmd.CombinedOutput(); runErr != nil {
		// A commit SHA is not a valid --branch value; retry as a full clone and
		// check the ref out afterwards.
		if spec.Ref != "" && !spec.Full {
			cleanup()
			return Clone(ctx, CloneSpec{URL: spec.URL, Ref: spec.Ref, Full: true})
		}
		cleanup()
		return "", noop, fmt.Errorf("git clone %s: %w: %s",
			Redact(spec.URL), runErr, strings.TrimSpace(string(out)))
	}

	if spec.Ref != "" && spec.Full {
		checkout := exec.CommandContext(ctx, "git", "-C", dir, "checkout", "--quiet", spec.Ref)
		if out, coErr := checkout.CombinedOutput(); coErr != nil {
			cleanup()
			return "", noop, fmt.Errorf("git checkout %s: %w: %s",
				spec.Ref, coErr, strings.TrimSpace(string(out)))
		}
	}

	return dir, cleanup, nil
}

// HasToken reports whether a credential for HTTPS cloning is present in the
// environment. Callers use it to choose between an HTTPS URL, which the token
// authenticates, and SSH, which needs a key on disk.
func HasToken() bool { return firstEnv(TokenEnvVars) != "" }

// IsRemoteURL reports whether target names a remote repository rather than a
// local path. It accepts scheme URLs, scp-style git addresses, and bare
// host/org/repo forms for the common forges.
func IsRemoteURL(target string) bool {
	t := strings.TrimSpace(target)
	switch {
	case t == "":
		return false
	case strings.HasPrefix(t, "http://"), strings.HasPrefix(t, "https://"),
		strings.HasPrefix(t, "ssh://"), strings.HasPrefix(t, "git://"):
		return true
	case strings.HasPrefix(t, "git@"):
		return true
	}

	// Bare forge paths: github.com/org/repo, gitlab.com/org/repo…
	for _, host := range []string{"github.com/", "gitlab.com/", "bitbucket.org/", "dev.azure.com/"} {
		if strings.HasPrefix(t, host) {
			return true
		}
	}
	return false
}

// NormalizeURL turns a bare forge path into an https URL and leaves every
// other form untouched.
func NormalizeURL(target string) string {
	t := strings.TrimSpace(target)
	if strings.Contains(t, "://") || strings.HasPrefix(t, "git@") {
		return t
	}
	return "https://" + t
}

// withCredentials injects a token from the environment into an HTTPS URL that
// carries no credentials of its own. Other URL forms are returned unchanged so
// SSH keys keep working.
func withCredentials(raw string) string {
	if !strings.HasPrefix(raw, "https://") {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil {
		return raw
	}
	token := firstEnv(TokenEnvVars)
	if token == "" {
		return raw
	}
	// The username is ignored by GitHub/GitLab when a token is the password;
	// x-access-token is the convention GitHub documents.
	u.User = url.UserPassword("x-access-token", token)
	return u.String()
}

func firstEnv(names []string) string {
	for _, n := range names {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v
		}
	}
	return ""
}

// Redact removes any embedded credential from a URL so it is safe to print.
func Redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = url.User("***")
	return u.String()
}
