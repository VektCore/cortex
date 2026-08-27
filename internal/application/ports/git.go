package ports

import (
	"context"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/domain/scan"
)

// GitRepository exposes the minimum git operations Cortex needs.
// Implementations may shell out to the git binary or use a library.
type GitRepository interface {
	CurrentRevision(ctx context.Context, path string) mo.Result[scan.Revision]
	ChangedFiles(ctx context.Context, path, baseRef string) mo.Result[[]string]

	// ChangedLines returns the exact lines a diff against baseRef added or
	// modified. It is what makes a "no new critical in this pull request" gate
	// possible: a repository carrying 4000 inherited findings can adopt that
	// gate today, an absolute one never.
	ChangedLines(ctx context.Context, path, baseRef string) mo.Result[ChangedLines]
}
