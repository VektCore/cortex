package usecases_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/application/usecases"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/scan"
)

func newScanCompleted(t *testing.T) scan.Scan {
	t.Helper()
	id, err := scan.NewID("scan-1").Get()
	require.NoError(t, err)
	s := scan.New(id, mkRevision())
	running, err := s.Start(time.Now()).Get()
	require.NoError(t, err)
	done, err := running.Complete(time.Now(), nil).Get()
	require.NoError(t, err)
	return done
}

func TestPublishResults_FanOutToAll(t *testing.T) {
	t.Parallel()
	a := &fakePublisher{name: "korvlabs"}
	b := &fakePublisher{name: "github_code_scanning"}
	c := &fakePublisher{name: "filesystem"}

	uc := usecases.NewPublishResults(usecases.PublishResultsDeps{
		Publishers: map[string]ports.Publisher{a.name: a, b.name: b, c.name: c},
		Logger:     noopLogger{},
	})

	resp := uc.Execute(context.Background(), dto.PublishResultsRequest{
		Scan:     newScanCompleted(t),
		Findings: []finding.Finding{mkFinding("a.go", 0, "x")},
		SARIF:    []byte(`{"runs":[]}`),
	})
	assert.Len(t, resp.Receipts, 3)
	assert.Empty(t, resp.Errors)
	assert.Equal(t, 1, a.calls)
	assert.Equal(t, 1, b.calls)
	assert.Equal(t, 1, c.calls)
}

func TestPublishResults_FailureIsIsolated(t *testing.T) {
	t.Parallel()
	ok := &fakePublisher{name: "korvlabs"}
	bad := &fakePublisher{name: "github", err: errors.New("forbidden")}

	uc := usecases.NewPublishResults(usecases.PublishResultsDeps{
		Publishers: map[string]ports.Publisher{ok.name: ok, bad.name: bad},
		Logger:     noopLogger{},
	})

	resp := uc.Execute(context.Background(), dto.PublishResultsRequest{
		Scan:  newScanCompleted(t),
		SARIF: []byte(`{}`),
	})
	assert.Len(t, resp.Receipts, 1)
	assert.Equal(t, "korvlabs", resp.Receipts[0].Publisher)
	assert.Len(t, resp.Errors, 1)
	assert.Contains(t, resp.Errors, "github")
}

func TestPublishResults_TargetedSubset(t *testing.T) {
	t.Parallel()
	a := &fakePublisher{name: "korvlabs"}
	b := &fakePublisher{name: "filesystem"}

	uc := usecases.NewPublishResults(usecases.PublishResultsDeps{
		Publishers: map[string]ports.Publisher{a.name: a, b.name: b},
		Logger:     noopLogger{},
	})

	resp := uc.Execute(context.Background(), dto.PublishResultsRequest{
		Scan:    newScanCompleted(t),
		SARIF:   []byte(`{}`),
		Targets: []string{"filesystem"},
	})
	assert.Len(t, resp.Receipts, 1)
	assert.Equal(t, 0, a.calls)
	assert.Equal(t, 1, b.calls)
}

func TestPublishResults_UnknownTargetReportedAsError(t *testing.T) {
	t.Parallel()
	uc := usecases.NewPublishResults(usecases.PublishResultsDeps{
		Publishers: map[string]ports.Publisher{},
		Logger:     noopLogger{},
	})
	resp := uc.Execute(context.Background(), dto.PublishResultsRequest{
		Scan:    newScanCompleted(t),
		Targets: []string{"nonexistent"},
	})
	assert.Contains(t, resp.Errors, "nonexistent")
}
