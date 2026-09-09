package httpapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A pipeline that wants the exact commit it is building sends a SHA. Prefixing
// that with refs/heads/ produces a ref that names no branch, and GitHub rejects
// the whole upload — which used to take the commit status down with it.
func TestQualifyRef(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in   string
		want string
	}{
		"a branch":              {"main", "refs/heads/main"},
		"a branch with slashes": {"feature/upload-gate", "refs/heads/feature/upload-gate"},
		"an already-full ref":   {"refs/heads/main", "refs/heads/main"},
		"a tag ref":             {"refs/tags/v1.2.3", "refs/tags/v1.2.3"},
		"a full SHA":            {"9f2a1c4e8b7d6a5f4e3c2b1a0987654321fedcba", ""},
		"an abbreviated SHA":    {"9f2a1c4", ""},
		"empty":                 {"", ""},
		"padded":                {"  main  ", "refs/heads/main"},
		"hex-looking branch":    {"cafe", "refs/heads/cafe"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, qualifyRef(tc.in))
		})
	}
}
