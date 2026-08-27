package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/domain/gate"
	"github.com/vektcore/cortex/internal/infrastructure/config"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), ".cortex.yaml")
	require.NoError(t, os.WriteFile(f, []byte(content), 0o644))
	return f
}

func TestLoad_Defaults_WhenFileMissing(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load("/tmp/cortex-test-nonexistent-file.yaml")
	require.NoError(t, err)
	assert.True(t, cfg.Scanners.Semgrep.Enabled)
	assert.True(t, cfg.Scanners.Bandit.Enabled)
	assert.True(t, cfg.Scanners.Gosec.Enabled)
	assert.True(t, cfg.Scanners.Gitleaks.Enabled)
	assert.False(t, cfg.Scanners.Spotbugs.Enabled)
	assert.True(t, cfg.Publishers.Filesystem.Enabled)
	assert.Equal(t, "results/", cfg.Publishers.Filesystem.OutputDir)
}

func TestLoad_ParsesGateRules(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `
version: "1"
gate:
  rules:
    - name: no-critical
      severity: critical
      threshold: ">=1"
    - name: limit-high
      severity: high
      threshold: ">5"
`)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	require.Len(t, cfg.Gate.Rules, 2)
	assert.Equal(t, "no-critical", cfg.Gate.Rules[0].Name)
	assert.Equal(t, ">=1", cfg.Gate.Rules[0].Threshold)
}

func TestConfig_BuildPolicy_DefaultWhenNoRules(t *testing.T) {
	t.Parallel()
	cfg, _ := config.Load("/tmp/no-such.yaml")
	policy, err := cfg.BuildPolicy()
	require.NoError(t, err)
	assert.False(t, policy.IsEmpty())
}

func TestConfig_BuildPolicy_OneRuleBuilt(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `
gate:
  rules:
    - name: no-critical
      severity: critical
      threshold: ">=1"
`)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	policy, err := cfg.BuildPolicy()
	require.NoError(t, err)
	rules := policy.Rules()
	require.Len(t, rules, 1)
	assert.Equal(t, "no-critical", rules[0].Name())
	assert.Equal(t, gate.OpGreaterEqual, rules[0].Threshold().Op())
	assert.Equal(t, 1, rules[0].Threshold().Value())
}

func TestConfig_BuildPolicy_ThresholdVariants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		threshold string
		wantOp    gate.Operator
		wantVal   int
	}{
		{">=1", gate.OpGreaterEqual, 1},
		{">5", gate.OpGreater, 5},
		{"<=3", gate.OpLessEqual, 3},
		{"<2", gate.OpLess, 2},
		{"=0", gate.OpEqual, 0},
		{"10", gate.OpGreaterEqual, 10},
	}
	for _, tc := range tests {
		t.Run(tc.threshold, func(t *testing.T) {
			t.Parallel()
			path := writeConfig(t, `gate:
  rules:
    - name: r
      severity: critical
      threshold: "`+tc.threshold+`"
`)
			cfg, err := config.Load(path)
			require.NoError(t, err)
			policy, err := cfg.BuildPolicy()
			require.NoError(t, err)
			rules := policy.Rules()
			require.Len(t, rules, 1)
			assert.Equal(t, tc.wantOp, rules[0].Threshold().Op())
			assert.Equal(t, tc.wantVal, rules[0].Threshold().Value())
		})
	}
}

func TestLoad_DisableScannerViaConfig(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `
scanners:
  semgrep:
    enabled: false
  bandit:
    enabled: true
`)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	assert.False(t, cfg.Scanners.Semgrep.Enabled)
	assert.True(t, cfg.Scanners.Bandit.Enabled)
}

// Secrets belong in the environment, and every example config in this
// repository is written that way. Before this was implemented the placeholders
// loaded as literals, so a server deployed from the documented example accepted
// the string "${CLIENT_ACME_KEY}" as a valid API key.
func TestLoad_ExpandsEnvironmentReferences(t *testing.T) {
	t.Setenv("CORTEX_TEST_CLIENT_KEY", "sk-real-value")
	t.Setenv("CORTEX_TEST_WEBHOOK", "wh-real-value")

	dir := t.TempDir()
	path := filepath.Join(dir, "cortex.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`version: "1"
server:
  api_keys:
    - name: acme
      key: ${CORTEX_TEST_CLIENT_KEY}
  webhook_secret: ${CORTEX_TEST_WEBHOOK}
publishers:
  korvlabs:
    api_key: ${CORTEX_TEST_CLIENT_KEY}
`), 0o600))

	cfg, err := config.Load(path)
	require.NoError(t, err)

	require.Len(t, cfg.Server.APIKeys, 1)
	assert.Equal(t, "sk-real-value", cfg.Server.APIKeys[0].Key)
	assert.Equal(t, "wh-real-value", cfg.Server.WebhookSecret)
	assert.Equal(t, "sk-real-value", cfg.Publishers.KorvLabs.APIKey)
}

// An undefined variable must not stay literal: an empty credential is rejected
// downstream, a literal one silently authenticates.
func TestLoad_UndefinedReferenceBecomesEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cortex.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`version: "1"
server:
  api_keys:
    - name: acme
      key: ${DEFINITELY_NOT_SET_ANYWHERE}
`), 0o600))

	cfg, err := config.Load(path)
	require.NoError(t, err)

	require.Len(t, cfg.Server.APIKeys, 1)
	assert.Empty(t, cfg.Server.APIKeys[0].Key,
		"a placeholder that resolves to nothing must not become a usable key")
}

// A lone "$" is not a reference: rule patterns and passwords contain them.
func TestLoad_LeavesBareDollarsAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cortex.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`version: "1"
publishers:
  korvlabs:
    api_key: "pa$$word-with-dollars"
`), 0o600))

	cfg, err := config.Load(path)
	require.NoError(t, err)
	assert.Equal(t, "pa$$word-with-dollars", cfg.Publishers.KorvLabs.APIKey)
}
