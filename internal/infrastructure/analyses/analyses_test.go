package analyses_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/infrastructure/analyses"
)

// A misconfigured server must fail at startup, not hand out a store that
// accepts analyses and forgets them until a client asks for a result.
func TestOpen_WithoutADSN(t *testing.T) {
	t.Parallel()

	store, err := analyses.Open(context.Background(), "")

	require.ErrorIs(t, err, analyses.ErrNoDSN)
	assert.Nil(t, store)
}

// The tags are what a polling client reads. They are asserted here because
// renaming one breaks every caller without breaking the build.
func TestReport_JSONFieldNamesAreTheClientContract(t *testing.T) {
	t.Parallel()

	started := time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)
	encoded, err := json.Marshal(analyses.Report{
		ID:            "a1",
		Owner:         "acme-corp",
		Project:       "acme-corp/acme",
		Source:        "git",
		Repository:    "git@example.com:acme/app.git",
		Ref:           "refs/heads/main",
		Commit:        "deadbeef",
		Status:        "completed",
		Gate:          "failed",
		Findings:      3,
		BySeverity:    map[string]int{"critical": 1},
		NewFindings:   2,
		Reopened:      1,
		Resolved:      4,
		ScannersRan:   5,
		ScannerErrors: map[string]string{"gosec": "not on PATH"},
		KnownBefore:   7,
		RequestedBy:   "ci",
		Error:         "boom",
		QueuedAt:      started,
		StartedAt:     &started,
		FinishedAt:    &started,
	})
	require.NoError(t, err)

	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &fields))

	for _, name := range []string{
		"id", "owner", "project", "source", "repository", "ref", "commit", "status", "gate",
		"findings", "by_severity", "new_findings", "reopened", "resolved",
		"scanners_ran", "scanner_errors", "known_before", "requested_by", "error",
		"queued_at", "started_at", "finished_at",
	} {
		assert.Contains(t, fields, name)
	}
}

// A queued analysis has no gate, no error and no timestamps yet. Emitting them
// as empty strings would make a client believe the gate had already run.
func TestReport_OptionalFieldsAreOmittedWhileTheyAreUnknown(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(analyses.Report{
		ID: "a1", Project: "acme", Source: "upload", Status: "queued",
		QueuedAt: time.Now().UTC(),
	})
	require.NoError(t, err)

	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &fields))

	for _, name := range []string{
		"gate", "error", "started_at", "finished_at", "by_severity",
		"scanner_errors", "repository", "ref", "commit", "requested_by", "owner",
	} {
		assert.NotContains(t, fields, name)
	}
	assert.Contains(t, fields, "findings", "a count of zero is a fact, not an absence")
}
