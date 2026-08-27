package cli

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/infrastructure/config"
)

func buildIgnoreFilters(rules []config.IgnoreRule) []dto.IgnoreFilter {
	out := make([]dto.IgnoreFilter, 0, len(rules))
	for _, r := range rules {
		f := dto.IgnoreFilter{RuleID: r.RuleID, PathPrefix: r.PathPrefix}
		if r.Expires != "" {
			if t, err := time.Parse("2006-01-02", r.Expires); err == nil {
				f.ExpiresAt = t
			}
		}
		out = append(out, f)
	}
	return out
}

func applyIgnoreFilters(findings []finding.Finding, ignores []dto.IgnoreFilter) []finding.Finding {
	if len(ignores) == 0 {
		return findings
	}
	now := time.Now()
	out := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		suppressed := false
		for _, ig := range ignores {
			if matchesIgnore(f, ig, now) {
				suppressed = true
				break
			}
		}
		if !suppressed {
			out = append(out, f)
		}
	}
	return out
}

func matchesIgnore(f finding.Finding, ig dto.IgnoreFilter, now time.Time) bool {
	if !ig.ExpiresAt.IsZero() && now.After(ig.ExpiresAt) {
		return false
	}
	if ig.RuleID != "" && !strings.EqualFold(f.RuleID().String(), ig.RuleID) {
		return false
	}
	if ig.PathPrefix != "" && !matchesPath(f.Location().File(), ig.PathPrefix) {
		return false
	}
	return true
}

// matchesPath decides whether an allowlist path pattern covers a finding's
// file. Three forms are accepted, because a scanner may report a path relative
// to the repository, relative to the scan target, or absolute:
//
//	tests/                → any path starting with it, and any nested
//	                        "tests/" directory segment
//	services/*/tests/**   → glob, matched against the whole path
//	/src/vendor           → plain prefix
func matchesPath(file, pattern string) bool {
	if strings.HasPrefix(file, pattern) {
		return true
	}
	if matched, err := filepath.Match(pattern, file); err == nil && matched {
		return true
	}
	// A directory pattern also matches when it appears anywhere in the path,
	// so "tests/" covers services/vulnerability/tests/test_domain.py.
	segment := strings.Trim(pattern, "/")
	if segment == "" {
		return false
	}
	return strings.Contains(file, "/"+segment+"/") || strings.HasSuffix(file, "/"+segment)
}
