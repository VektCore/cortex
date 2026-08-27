package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/infrastructure/reporters/markdown"
)

func newPipelineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pipeline [path]",
		Short: "Run the full chain: detect → scan → aggregate → verify → report → publish",
		Long: `One-shot command for CI. Runs every stage end-to-end and returns the
exit code from the Quality Gate (or non-zero if any earlier stage errors).`,
		Args: cobra.MaximumNArgs(1),
	}
	cmd.Flags().Bool("dry-run", false, "execute everything except publish")
	cmd.Flags().String("results-dir", "results/", "directory for SARIF artifacts")
	cmd.Flags().Bool("no-track", false,
		"do not update the vulnerability state (use for pull-request scans)")
	addRemoteFlags(cmd)

	cmd.RunE = runPipeline

	return cmd
}

func runPipeline(cmd *cobra.Command, args []string) error {
	targetPath, cleanup, err := resolveTarget(cmd, firstArgOr(args, "."))
	if err != nil {
		return err
	}
	defer cleanup()

	env, err := loadEnv(cmd)
	if err != nil {
		return err
	}
	policy, err := env.policy()
	if err != nil {
		return err
	}

	// An explicit --results-dir wins over the configured filesystem publisher,
	// so several runs (one per repository, say) can keep their artifacts apart
	// without a config file each. Left untouched when the flag is absent.
	if cmd.Flags().Changed("results-dir") {
		dir, _ := cmd.Flags().GetString("results-dir")
		env.cfg.Publishers.Filesystem.OutputDir = dir
	}

	dryRun, _ := cmd.Flags().GetBool("dry-run")

	resp, pipeErr := buildPipeline(env.cfg, env.logger).Execute(cmd.Context(), dto.PipelineRequest{
		TargetPath:   targetPath,
		Policy:       policy,
		Baseline:     shared.None[[]finding.Finding](),
		DryRun:       dryRun,
		Ignores:      buildIgnoreFilters(env.cfg.Ignore),
		Settings:     env.cfg.ScannerSettings(),
		Exclude:      env.cfg.ExcludePatterns(),
		Escalations:  env.escalations,
		CrossScanner: env.cfg.CrossScannerDedup(),
		Reachability: env.cfg.ReachabilitySettings(),
	}).Get()
	if pipeErr != nil {
		return scannerErr(fmt.Sprintf("pipeline: %v", pipeErr))
	}

	// Per-scanner and per-publisher failures are non-fatal by design.
	for _, e := range resp.Errors {
		env.logger.Warn("non-fatal pipeline error", ports.F("error", e.Error()))
	}

	if repErr := markdown.New().Report(
		cmd.OutOrStdout(), resp.Scan, resp.Findings, resp.Verdict,
	); repErr != nil {
		env.logger.Warn("markdown render failed", ports.F("error", repErr.Error()))
	}

	if isGitHubActions() {
		emitGitHubAnnotations(cmd.OutOrStdout(), resp.Findings)
	}

	// The history is updated even when the gate fails: a blocked merge is still
	// an observation of what the repository contains. Doing it here rather than
	// inside the pipeline service keeps the service free of the state port.
	noTrack, _ := cmd.Flags().GetBool("no-track")
	if err := reconcileAndReport(cmd, env.cfg, env.logger, resp.Findings, !noTrack); err != nil {
		return err
	}

	if resp.Verdict.Failed() {
		return gateFailedErr("quality gate failed")
	}
	return nil
}
