package trivy_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/infrastructure/sarif"
	"github.com/vektcore/cortex/internal/infrastructure/scanners/trivy"
)

func TestScanner_Identity(t *testing.T) {
	t.Parallel()

	s := trivy.New(sarif.New(), "")

	assert.Equal(t, "trivy", string(s.Name()))
	assert.Len(t, s.SupportedLanguages(), 6)
	assert.Contains(t, s.SupportedLanguages(), shared.LanguagePython)
}

func TestScanner_UnavailableBinary(t *testing.T) {
	t.Parallel()

	s := trivy.New(sarif.New(), "definitely-not-a-real-binary-trivy")
	assert.False(t, s.Available(context.Background()))

	_, err := s.Scan(context.Background(), ports.ScanRequest{TargetPath: "."}).Get()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trivy")
}

func TestScanner_NonSARIFOutputIsAnError(t *testing.T) {
	t.Parallel()

	s := trivy.New(sarif.New(), "echo")

	_, err := s.Scan(context.Background(), ports.ScanRequest{TargetPath: "."}).Get()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SARIF")
}
