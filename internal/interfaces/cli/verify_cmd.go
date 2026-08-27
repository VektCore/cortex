package cli

import (
	"github.com/samber/mo"
	"github.com/spf13/cobra"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/application/usecases"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/scan"
	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/infrastructure/reporters/markdown"
	infrasarif "github.com/vektcore/cortex/internal/infrastructure/sarif"
)

func newVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify [sarif-file]",
		Short: "Apply the Quality Gate (exit non-zero on failure)",
		Long: `Reads a (merged) SARIF file and evaluates it against the gate policy.
Returns exit code 1 if the gate fails, 0 otherwise. This is the command CI
pipelines should rely on to block merges.`,
		Args: cobra.MaximumNArgs(1),
	}
	cmd.Flags().Bool("fail-on-critical", true, "fail if any CRITICAL finding is present")
	cmd.Flags().String("baseline", "", "path to baseline SARIF (only count new findings)")
	cmd.Flags().Bool("new-only", false,
		"gate only on vulnerabilities the tracked state has never seen")
	cmd.Flags().String("changed-since", "",
		"git ref: gate only on findings sitting on lines this branch changed (e.g. origin/main)")

	cmd.RunE = runVerify

	return cmd
}

func runVerify(cmd *cobra.Command, args []string) error {
	sarifFile := firstArgOr(args, "results/scan.sarif")

	env, err := loadEnv(cmd)
	if err != nil {
		return err
	}
	policy, err := env.policy()
	if err != nil {
		return err
	}

	codec := infrasarif.New()
	findings, _, err := readEnrichedSARIF(codec, sarifFile, env.cfg)
	if err != nil {
		return configErr(err.Error())
	}

	gateFindings, err := gateScope(cmd, env, findings)
	if err != nil {
		return err
	}

	baseline, err := loadBaseline(cmd, codec, env)
	if err != nil {
		return err
	}

	gateResp := usecases.NewApplyQualityGate().Execute(dto.ApplyQualityGateRequest{
		Findings: gateFindings,
		Policy:   policy,
		Baseline: baseline,
	})

	_ = markdown.New().Report(cmd.OutOrStdout(), scan.Scan{}, findings, gateResp.Verdict)

	if isGitHubActions() {
		emitGitHubAnnotations(cmd.OutOrStdout(), findings)
	}

	if gateResp.Verdict.Failed() {
		return gateFailedErr("quality gate failed")
	}
	return nil
}

// gateScope applies the allowlist and then narrows the gate to new or changed
// code when asked.
func gateScope(
	cmd *cobra.Command, env cmdEnv, findings []finding.Finding,
) ([]finding.Finding, error) {
	gateFindings := applyIgnoreFilters(findings, buildIgnoreFilters(env.cfg.Ignore))

	newOnly, _ := cmd.Flags().GetBool("new-only")
	changedSince, _ := cmd.Flags().GetString("changed-since")

	return narrowGateScope(cmd, env.cfg, gateFindings, newOnly, changedSince)
}

// loadBaseline reads the differential baseline, if one was given. It goes
// through the same normalization as the scan: an un-enriched baseline would make
// every enriched finding look new.
func loadBaseline(
	cmd *cobra.Command, codec ports.SarifCodec, env cmdEnv,
) (mo.Option[[]finding.Finding], error) {
	path, _ := cmd.Flags().GetString("baseline")
	if path == "" {
		return shared.None[[]finding.Finding](), nil
	}

	baseFindings, _, err := readEnrichedSARIF(codec, path, env.cfg)
	if err != nil {
		return shared.None[[]finding.Finding](), configErr(err.Error())
	}
	return shared.Some(baseFindings), nil
}
