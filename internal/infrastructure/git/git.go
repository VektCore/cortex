package git

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/scan"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// Repository implements ports.GitRepository by shelling out to the git binary.
// It never imports libgit2 or any C binding — just os/exec.
type Repository struct {
	binary string
}

// New returns a Repository using the git binary from PATH.
func New() *Repository { return &Repository{binary: "git"} }

// Ensure compile-time interface satisfaction.
var _ ports.GitRepository = (*Repository)(nil)

// CurrentRevision returns the HEAD commit hash and current branch name.
// On a detached HEAD (common in CI), branch is returned as empty string.
func (r *Repository) CurrentRevision(
	ctx context.Context,
	path string,
) mo.Result[scan.Revision] {
	commit, err := r.run(ctx, path, "rev-parse", "HEAD")
	if err != nil {
		return shared.Err[scan.Revision](fmt.Errorf("git rev-parse HEAD: %w", err))
	}

	branch, _ := r.run(ctx, path, "rev-parse", "--abbrev-ref", "HEAD")
	// "HEAD" means detached HEAD — treat as empty branch
	if branch == "HEAD" {
		branch = ""
	}

	return scan.NewRevision(commit, branch)
}

// ChangedFiles returns the list of files that differ between baseRef and HEAD.
// If baseRef is empty, compares against the parent commit (HEAD~1).
// Returns nil slice (not error) when the repository has a single commit.
func (r *Repository) ChangedFiles(
	ctx context.Context,
	path string,
	baseRef string,
) mo.Result[[]string] {
	if baseRef == "" {
		baseRef = "HEAD~1"
	}
	out, err := r.run(ctx, path, "diff", "--name-only", baseRef+"...HEAD")
	if err != nil {
		// Single-commit repo — HEAD~1 doesn't exist; return empty list
		return shared.Ok[[]string](nil)
	}
	if out == "" {
		return shared.Ok[[]string](nil)
	}
	lines := strings.Split(out, "\n")
	result := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			result = append(result, l)
		}
	}
	return shared.Ok(result)
}

// run executes a git subcommand inside path and returns trimmed stdout.
func (r *Repository) run(ctx context.Context, path string, args ...string) (string, error) {
	fullArgs := append([]string{"-C", path}, args...)
	cmd := exec.CommandContext(ctx, r.binary, fullArgs...)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(errBuf.String()))
	}
	return strings.TrimSpace(out.String()), nil
}
