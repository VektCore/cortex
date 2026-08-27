package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/ruleset"
	"github.com/vektcore/cortex/internal/infrastructure/config"
)

// readSARIF loads a SARIF document from disk and parses it into findings.
// Both forms are returned: publishers forward the raw bytes, reporters and the
// gate work on the domain findings.
func readSARIF(codec ports.SarifCodec, path string) ([]finding.Finding, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read SARIF %q: %w", path, err)
	}
	findings, parseErr := codec.Parse(raw).Get()
	if parseErr != nil {
		return nil, nil, fmt.Errorf("parse SARIF %q: %w", path, parseErr)
	}
	return findings, raw, nil
}

// countBySeverity summarises a finding set for human-readable output.
func countBySeverity(findings []finding.Finding) map[string]int {
	out := make(map[string]int, 5)
	for _, f := range findings {
		out[f.Severity().String()]++
	}
	return out
}

// printSeverityCounts writes the severity breakdown in descending order, which
// is how a reader scans it: worst first.
func printSeverityCounts(cmd *cobra.Command, findings []finding.Finding) {
	counts := countBySeverity(findings)
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n := counts[sev]; n > 0 {
			cmd.Printf("  %-10s %d\n", sev, n)
		}
	}
}

// enrich applies the normalization a scan applies, so a SARIF read back from
// disk gates exactly like the scan that produced it: CWEs filled from the
// static tables, severities escalated by weakness class, excluded paths
// dropped. Paths are not touched — they were normalized when the scan ran.
func enrich(findings []finding.Finding, cfg *config.Config) ([]finding.Finding, error) {
	escalations, err := cfg.SeverityEscalations()
	if err != nil {
		return nil, err
	}

	out := ruleset.EnrichCWE(findings)
	out = ruleset.Escalate(out, escalations)
	out = finding.ExcludePaths(out, cfg.ExcludePatterns())
	return out, nil
}

// readEnrichedSARIF is readSARIF followed by enrich — what every command that
// consumes an existing SARIF should use.
func readEnrichedSARIF(
	codec ports.SarifCodec, path string, cfg *config.Config,
) ([]finding.Finding, []byte, error) {
	findings, raw, err := readSARIF(codec, path)
	if err != nil {
		return nil, nil, err
	}
	enriched, err := enrich(findings, cfg)
	if err != nil {
		return nil, nil, err
	}
	return enriched, raw, nil
}
