package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/infrastructure/config"
	infrasarif "github.com/vektcore/cortex/internal/infrastructure/sarif"
)

// defaultBaselinePath is where the baseline lives unless overridden. Keeping it
// inside the repository lets CI commit an accepted-debt snapshot.
const defaultBaselinePath = ".cortex/baseline.sarif"

func newBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Create or refresh the baseline SARIF for differential gating",
		Long: `The baseline is a snapshot of accepted findings. "cortex verify --baseline"
counts only findings absent from it, so a pipeline can block new debt without
being blocked by the existing one.`,
	}
	cmd.AddCommand(newBaselineCreateCmd(), newBaselineShowCmd())
	return cmd
}

func newBaselineCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create [path]",
		Short: "Generate baseline from current state",
		Long: `Scans the target path and stores its deduplicated findings as the baseline.
With --from, an existing SARIF document is normalized into a baseline instead
of running the scanners again.`,
		Args: cobra.MaximumNArgs(1),
	}
	cmd.Flags().String("output", defaultBaselinePath, "baseline SARIF output path")
	cmd.Flags().String("from", "", "build the baseline from an existing SARIF file instead of scanning")
	addRemoteFlags(cmd)

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		targetPath := "."
		if len(args) > 0 {
			targetPath = args[0]
		}

		targetPath, cleanup, targetErr := resolveTarget(cmd, targetPath)
		if targetErr != nil {
			return targetErr
		}
		defer cleanup()

		outPath, _ := cmd.Flags().GetString("output")
		from, _ := cmd.Flags().GetString("from")
		cfgPath, _ := cmd.Root().PersistentFlags().GetString("config")
		logLevel, _ := cmd.Root().PersistentFlags().GetString("log-level")
		quiet, _ := cmd.Root().PersistentFlags().GetBool("quiet")

		cfg, err := config.Load(cfgPath)
		if err != nil {
			return configErr(fmt.Sprintf("load config: %v", err))
		}

		codec := infrasarif.New()

		findings, err := baselineFindings(cmd, cfg, codec, targetPath, from, logLevel, quiet)
		if err != nil {
			return err
		}
		findings = finding.Deduplicate(findings)

		doc, wErr := codec.Write(findings, ports.SarifMetadata{
			Tool:    "cortex-baseline",
			Version: version,
		}).Get()
		if wErr != nil {
			return scannerErr(fmt.Sprintf("write baseline SARIF: %v", wErr))
		}

		if mkErr := os.MkdirAll(filepath.Dir(outPath), 0o755); mkErr != nil {
			return scannerErr(fmt.Sprintf("create baseline dir: %v", mkErr))
		}
		if wfErr := os.WriteFile(outPath, doc, 0o600); wfErr != nil {
			return scannerErr(fmt.Sprintf("write %q: %v", outPath, wfErr))
		}

		cmd.Printf("baseline: %d finding(s)  →  %s\n", len(findings), outPath)
		return nil
	}

	return cmd
}

// baselineFindings sources the baseline content: either an existing SARIF
// document (--from) or a fresh scan of the target path.
func baselineFindings(
	cmd *cobra.Command,
	cfg *config.Config,
	codec ports.SarifCodec,
	targetPath, from, logLevel string,
	quiet bool,
) ([]finding.Finding, error) {
	if from != "" {
		findings, _, err := readEnrichedSARIF(codec, from, cfg)
		if err != nil {
			return nil, configErr(err.Error())
		}
		return findings, nil
	}

	escalations, escErr := cfg.SeverityEscalations()
	if escErr != nil {
		return nil, configErr(escErr.Error())
	}

	logger := buildLogger(logLevel, quiet)
	resp, scanErr := buildExecuteScan(cfg, codec, logger).Execute(cmd.Context(), dto.ExecuteScanRequest{
		TargetPath:   targetPath,
		Settings:     cfg.ScannerSettings(),
		Exclude:      cfg.ExcludePatterns(),
		Escalations:  escalations,
		Reachability: cfg.ReachabilitySettings(),
	}).Get()
	if scanErr != nil {
		return nil, scannerErr(fmt.Sprintf("baseline scan: %v", scanErr))
	}
	reportScannerErrors(cmd, resp.Errors)
	return resp.Findings, nil
}

func newBaselineShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show [baseline-file]",
		Short: "Print baseline summary",
		Args:  cobra.MaximumNArgs(1),
	}

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		path := defaultBaselinePath
		if len(args) > 0 {
			path = args[0]
		}

		findings, _, err := readSARIF(infrasarif.New(), path)
		if err != nil {
			return configErr(err.Error())
		}

		counts := countBySeverity(findings)
		severities := make([]string, 0, len(counts))
		for sev := range counts {
			severities = append(severities, sev)
		}
		sort.Strings(severities)

		cmd.Printf("baseline %s: %d finding(s)\n", path, len(findings))
		for _, sev := range severities {
			cmd.Printf("  %-10s %d\n", sev, counts[sev])
		}
		return nil
	}

	return cmd
}
