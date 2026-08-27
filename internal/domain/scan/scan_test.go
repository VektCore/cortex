package scan_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/scan"
)

func newScan(t *testing.T) scan.Scan {
	t.Helper()
	id, err := scan.NewID("scan-1").Get()
	require.NoError(t, err)
	rev, err := scan.NewRevision("abc123", "main").Get()
	require.NoError(t, err)
	return scan.New(id, rev)
}

func TestNew_StartsQueued(t *testing.T) {
	t.Parallel()
	s := newScan(t)
	assert.Equal(t, scan.StatusQueued, s.Status())
	assert.Len(t, s.Events(), 1)
	assert.Equal(t, "scan.queued", s.Events()[0].EventName())
}

func TestStart_QueuedToRunning(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	r := newScan(t).Start(now)
	s, err := r.Get()
	require.NoError(t, err)
	assert.Equal(t, scan.StatusRunning, s.Status())
	assert.Equal(t, now, s.StartedAt())
	assert.Equal(t, "scan.started", s.Events()[len(s.Events())-1].EventName())
}

func TestStart_RejectsNonQueued(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	running, err := newScan(t).Start(now).Get()
	require.NoError(t, err)
	_, err = running.Start(now).Get()
	assert.Error(t, err)
}

func TestComplete_RecordsFindingsAndDuration(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	end := start.Add(45 * time.Second)

	running, err := newScan(t).Start(start).Get()
	require.NoError(t, err)

	completed, err := running.Complete(end, []finding.Fingerprint{"fp1", "fp2", "fp3"}).Get()
	require.NoError(t, err)

	assert.Equal(t, scan.StatusCompleted, completed.Status())
	assert.Equal(t, 3, len(completed.Findings()))
	assert.Equal(t, 45*time.Second, completed.Duration())
}

func TestComplete_RejectsQueued(t *testing.T) {
	t.Parallel()
	_, err := newScan(t).Complete(time.Now(), nil).Get()
	assert.Error(t, err)
}

func TestFail_FromAnyNonTerminal(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()

	queued := newScan(t)
	failed, err := queued.Fail(now, "boom").Get()
	require.NoError(t, err)
	assert.Equal(t, scan.StatusFailed, failed.Status())
	assert.Equal(t, "boom", failed.Failure())

	// Failing twice is rejected.
	_, err = failed.Fail(now, "second").Get()
	assert.Error(t, err)
}

func TestImmutability_OriginalUnchangedAfterTransition(t *testing.T) {
	t.Parallel()
	original := newScan(t)
	_, err := original.Start(time.Now()).Get()
	require.NoError(t, err)
	// Original is still Queued — transitions returned a new instance.
	assert.Equal(t, scan.StatusQueued, original.Status())
	assert.Len(t, original.Events(), 1)
}

func TestStatus_IsTerminal(t *testing.T) {
	t.Parallel()
	assert.False(t, scan.StatusQueued.IsTerminal())
	assert.False(t, scan.StatusRunning.IsTerminal())
	assert.True(t, scan.StatusCompleted.IsTerminal())
	assert.True(t, scan.StatusFailed.IsTerminal())
}
