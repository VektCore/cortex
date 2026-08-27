package usecases_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/application/usecases"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/scan"
	"github.com/vektcore/cortex/internal/domain/shared"
)

func newExecuteScan(registry *fakeRegistry, detector *fakeDetector, git *fakeGit) *usecases.ExecuteScan {
	return usecases.NewExecuteScan(usecases.ExecuteScanDeps{
		Registry: registry,
		Detector: detector,
		Git:      git,
		IDGen:    &fakeIDGen{},
		Clock:    fixedClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		Logger:   noopLogger{},
	})
}

func TestExecuteScan_HappyPath(t *testing.T) {
	t.Parallel()
	semgrep := &fakeScanner{
		name:  "semgrep",
		langs: []shared.Language{shared.LanguagePython},
		findings: []finding.Finding{
			mkFinding("py/a.py", shared.SeverityHigh, "semgrep"),
			mkFinding("py/b.py", shared.SeverityCritical, "semgrep"),
		},
		sarif: []byte(`{"runs":[]}`),
	}
	bandit := &fakeScanner{
		name:  "bandit",
		langs: []shared.Language{shared.LanguagePython},
		findings: []finding.Finding{
			mkFinding("py/c.py", shared.SeverityMedium, "bandit"),
		},
		sarif: []byte(`{"runs":[]}`),
	}

	uc := newExecuteScan(
		newFakeRegistry(semgrep, bandit),
		&fakeDetector{languages: []shared.Language{shared.LanguagePython}},
		&fakeGit{revision: mkRevision()},
	)

	resp, err := uc.Execute(context.Background(), dto.ExecuteScanRequest{
		TargetPath: "/repo",
	}).Get()
	require.NoError(t, err)

	assert.Equal(t, scan.StatusCompleted, resp.Scan.Status())
	assert.Len(t, resp.Findings, 3, "two semgrep + one bandit")
	assert.Equal(t, 1, semgrep.calls)
	assert.Equal(t, 1, bandit.calls)
	assert.Empty(t, resp.Errors)
	assert.Contains(t, resp.PerScanner, finding.ScannerName("semgrep"))
	assert.Contains(t, resp.PerScanner, finding.ScannerName("bandit"))
}

func TestExecuteScan_AutoDetectsLanguages(t *testing.T) {
	t.Parallel()
	pyScanner := &fakeScanner{name: "bandit", langs: []shared.Language{shared.LanguagePython}}
	jsScanner := &fakeScanner{name: "eslint", langs: []shared.Language{shared.LanguageJavaScript}}

	uc := newExecuteScan(
		newFakeRegistry(pyScanner, jsScanner),
		&fakeDetector{languages: []shared.Language{shared.LanguagePython}}, // only Python detected
		&fakeGit{revision: mkRevision()},
	)

	_, err := uc.Execute(context.Background(), dto.ExecuteScanRequest{TargetPath: "/r"}).Get()
	require.NoError(t, err)
	assert.Equal(t, 1, pyScanner.calls, "bandit should run")
	assert.Equal(t, 0, jsScanner.calls, "eslint should NOT run (no JS detected)")
}

func TestExecuteScan_ExplicitScannerOverridesAutodetect(t *testing.T) {
	t.Parallel()
	pyScanner := &fakeScanner{name: "bandit", langs: []shared.Language{shared.LanguagePython}}
	jsScanner := &fakeScanner{name: "eslint", langs: []shared.Language{shared.LanguageJavaScript}}

	uc := newExecuteScan(
		newFakeRegistry(pyScanner, jsScanner),
		&fakeDetector{languages: []shared.Language{shared.LanguagePython}},
		&fakeGit{revision: mkRevision()},
	)

	_, err := uc.Execute(context.Background(), dto.ExecuteScanRequest{
		TargetPath: "/r",
		Scanners:   []finding.ScannerName{"eslint"},
	}).Get()
	require.NoError(t, err)
	assert.Equal(t, 0, pyScanner.calls)
	assert.Equal(t, 1, jsScanner.calls)
}

func TestExecuteScan_ScannerErrorDoesNotAbort(t *testing.T) {
	t.Parallel()
	ok := &fakeScanner{
		name: "semgrep", langs: []shared.Language{shared.LanguagePython},
		findings: []finding.Finding{mkFinding("a.py", shared.SeverityHigh, "semgrep")},
	}
	broken := &fakeScanner{
		name: "bandit", langs: []shared.Language{shared.LanguagePython},
		err: errors.New("bandit binary not found"),
	}

	uc := newExecuteScan(
		newFakeRegistry(ok, broken),
		&fakeDetector{languages: []shared.Language{shared.LanguagePython}},
		&fakeGit{revision: mkRevision()},
	)

	resp, err := uc.Execute(context.Background(), dto.ExecuteScanRequest{TargetPath: "/r"}).Get()
	require.NoError(t, err, "use case must not fail when one scanner errors")
	assert.Len(t, resp.Findings, 1)
	assert.Len(t, resp.Errors, 1)
	assert.Contains(t, resp.Errors, finding.ScannerName("bandit"))
}

func TestExecuteScan_GitFailureDegradesToUnknownRevision(t *testing.T) {
	t.Parallel()
	sc := &fakeScanner{
		name:     "semgrep",
		langs:    []shared.Language{shared.LanguagePython},
		findings: []finding.Finding{mkFinding("py/a.py", shared.SeverityHigh, "semgrep")},
		sarif:    []byte(`{"runs":[]}`),
	}
	uc := newExecuteScan(
		newFakeRegistry(sc),
		&fakeDetector{languages: []shared.Language{shared.LanguagePython}},
		&fakeGit{err: errors.New("not a git repository")},
	)

	resp, err := uc.Execute(context.Background(), dto.ExecuteScanRequest{TargetPath: "/r"}).Get()
	require.NoError(t, err, "a non-repository target must still be scannable")
	assert.True(t, resp.Scan.Revision().IsUnknown())
	assert.Len(t, resp.Findings, 1)
}
