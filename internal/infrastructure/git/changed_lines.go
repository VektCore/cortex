package git

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// hunkHeader captures the destination side of a unified diff header:
//
//	@@ -12,7 +14,9 @@ func foo()
//
// giving start line 14 and length 9. A missing length means 1.
var hunkHeader = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

// ChangedLines returns the lines added or modified relative to baseRef.
//
// Only the destination side matters: a deleted line cannot hold a finding. The
// diff runs with zero context (-U0) so the ranges are exactly what changed
// rather than what surrounds it — a gate on "new code" must not fire on the
// three untouched lines above the edit.
func (r *Repository) ChangedLines(
	ctx context.Context, path, baseRef string,
) mo.Result[ports.ChangedLines] {
	if strings.TrimSpace(baseRef) == "" {
		return shared.Err[ports.ChangedLines](
			fmt.Errorf("git changed lines: no base ref given"))
	}

	// The three-dot form compares against the merge base, which is what a pull
	// request shows: changes made on this branch, not changes the base picked up
	// meanwhile.
	out, err := r.run(ctx, path, "diff", "--unified=0", "--no-color",
		"--diff-filter=d", baseRef+"...HEAD")
	if err != nil {
		// A shallow clone has no merge base; fall back to a direct comparison.
		out, err = r.run(ctx, path, "diff", "--unified=0", "--no-color",
			"--diff-filter=d", baseRef)
		if err != nil {
			return shared.Err[ports.ChangedLines](
				fmt.Errorf("git changed lines against %q: %w", baseRef, err))
		}
	}

	return shared.Ok(parseUnifiedDiff(out))
}

func parseUnifiedDiff(diff string) ports.ChangedLines {
	changed := make(ports.ChangedLines)
	current := ""

	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "+++ b/"):
			current = strings.TrimPrefix(line, "+++ b/")
		case strings.HasPrefix(line, "+++ "):
			// "+++ /dev/null" — the file was deleted; nothing to attribute.
			current = ""
		case strings.HasPrefix(line, "@@"):
			if current == "" {
				continue
			}
			if r, ok := parseHunk(line); ok {
				changed[current] = append(changed[current], r)
			}
		}
	}
	return changed
}

func parseHunk(header string) (ports.LineRange, bool) {
	match := hunkHeader.FindStringSubmatch(header)
	if match == nil {
		return ports.LineRange{}, false
	}

	start, err := strconv.Atoi(match[1])
	if err != nil || start < 1 {
		return ports.LineRange{}, false
	}

	length := 1
	if match[2] != "" {
		parsed, lenErr := strconv.Atoi(match[2])
		if lenErr != nil {
			return ports.LineRange{}, false
		}
		// A zero-length destination hunk is a pure deletion.
		if parsed == 0 {
			return ports.LineRange{}, false
		}
		length = parsed
	}

	return ports.LineRange{Start: start, End: start + length - 1}, true
}
