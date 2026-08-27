package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/application/usecases"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/infrastructure/config"
	infrasarif "github.com/vektcore/cortex/internal/infrastructure/sarif"
)

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Run configured scanners and emit SARIF files",
		Long: `Executes every enabled scanner against the target in parallel and writes
one SARIF file per scanner under the output directory, plus a merged
scan.sarif that aggregate/verify/publish consume.

The target is a local path or a remote repository URL — github.com/org/repo,
https://…/repo.git, git@host:org/repo.git — which is cloned into a temporary
directory first (see --ref).

A scanner whose binary is missing from PATH is reported as a non-fatal error:
the remaining scanners still run.`,
		Args: cobra.MaximumNArgs(1),
	}

	cmd.Flags().StringSlice("scanner", nil,
		"scanners to run (default: all enabled). Example: --scanner semgrep,bandit")
	cmd.Flags().String("output", "results/", "directory for SARIF output")
	cmd.Flags().Int("parallel", 0, "max parallel scanners (0 = NumCPU)")
	cmd.Flags().Bool("no-track", false,
		"do not update the vulnerability state (use for pull-request scans)")
	addRemoteFlags(cmd)

	cmd.RunE = runScan

	return cmd
}

func runScan(cmd *cobra.Command, args []string) error {
	targetPath, cleanup, err := resolveTarget(cmd, firstArgOr(args, "."))
	if err != nil {
		return err
	}
	defer cleanup()

	env, err := loadEnv(cmd)
	if err != nil {
		return err
	}

	requested, _ := cmd.Flags().GetStringSlice("scanner")
	parallel, _ := cmd.Flags().GetInt("parallel")

	request := env.scanRequest(targetPath)
	request.Scanners = toScannerNames(requested)
	request.Parallelism = parallel

	codec := infrasarif.New()
	resp, scanErr := buildExecuteScan(env.cfg, codec, env.logger).
		Execute(cmd.Context(), request).Get()
	if scanErr != nil {
		return scannerErr(fmt.Sprintf("scan: %v", scanErr))
	}

	agg := usecases.NewAggregateFindings().Execute(dto.AggregateFindingsRequest{
		Inputs:       [][]finding.Finding{resp.Findings},
		CrossScanner: env.cfg.CrossScannerDedup(),
	})

	outputDir, _ := cmd.Flags().GetString("output")
	mergedPath, err := writeScanArtifacts(cmd, codec, outputDir, resp, agg.Findings)
	if err != nil {
		return err
	}

	cmd.Printf("\nscan %s  •  %d finding(s), %d after dedup  →  %s\n",
		resp.Scan.ID().String(), len(resp.Findings), len(agg.Findings), mergedPath)
	if agg.Corroborated > 0 {
		cmd.Printf("  %d weakness(es) corroborated by more than one scanner\n", agg.Corroborated)
	}
	printSeverityCounts(cmd, agg.Findings)
	reportScannerErrors(cmd, resp.Errors)

	noTrack, _ := cmd.Flags().GetBool("no-track")
	return reconcileAndReport(cmd, env.cfg, env.logger, agg.Findings, !noTrack)
}

// writeScanArtifacts persists one SARIF per scanner, the raw merge for
// traceability, and the canonical document downstream commands consume. Returns
// the path of the canonical one.
func writeScanArtifacts(
	cmd *cobra.Command,
	codec ports.SarifCodec,
	outputDir string,
	resp dto.ExecuteScanResponse,
	deduped []finding.Finding,
) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", scannerErr(fmt.Sprintf("create output dir %q: %v", outputDir, err))
	}

	docs, err := writePerScannerSARIF(cmd, outputDir, resp.PerScanner)
	if err != nil {
		return "", scannerErr(err.Error())
	}

	// The raw merge keeps each tool's own paths and severities; what
	// verify/report/publish consume has to be the canonical document.
	rawPath := filepath.Join(outputDir, "scan.raw.sarif")
	rawMerged, mergeErr := codec.Merge(docs).Get()
	if mergeErr != nil {
		return "", scannerErr(fmt.Sprintf("merge SARIF: %v", mergeErr))
	}
	if wErr := os.WriteFile(rawPath, rawMerged, 0o600); wErr != nil {
		return "", scannerErr(fmt.Sprintf("write %q: %v", rawPath, wErr))
	}

	mergedPath := filepath.Join(outputDir, "scan.sarif")
	canonical, writeErr := codec.Write(deduped, ports.SarifMetadata{
		Tool:     "cortex",
		Version:  version,
		Revision: resp.Scan.Revision(),
	}).Get()
	if writeErr != nil {
		return "", scannerErr(fmt.Sprintf("write canonical SARIF: %v", writeErr))
	}
	if wErr := os.WriteFile(mergedPath, canonical, 0o600); wErr != nil {
		return "", scannerErr(fmt.Sprintf("write %q: %v", mergedPath, wErr))
	}

	return mergedPath, nil
}

// writePerScannerSARIF persists one SARIF file per scanner and returns the raw
// documents in a stable order so the merge result is reproducible.
func writePerScannerSARIF(
	cmd *cobra.Command, outputDir string, perScanner map[finding.ScannerName][]byte,
) ([][]byte, error) {
	names := make([]string, 0, len(perScanner))
	for name := range perScanner {
		names = append(names, string(name))
	}
	sort.Strings(names)

	docs := make([][]byte, 0, len(names))
	for _, name := range names {
		raw := perScanner[finding.ScannerName(name)]
		if len(raw) == 0 {
			continue
		}
		path := filepath.Join(outputDir, name+".sarif")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			return nil, fmt.Errorf("write %q: %w", path, err)
		}
		cmd.Printf("  %-20s → %s\n", name, path)
		docs = append(docs, raw)
	}
	return docs, nil
}

func reportScannerErrors(cmd *cobra.Command, errs map[finding.ScannerName]error) {
	if len(errs) == 0 {
		return
	}
	names := make([]string, 0, len(errs))
	for name := range errs {
		names = append(names, string(name))
	}
	sort.Strings(names)

	cmd.Printf("\nskipped %d scanner(s):\n", len(names))
	for _, name := range names {
		cmd.Printf("  %-20s %v\n", name, errs[finding.ScannerName(name)])
	}
}

func toScannerNames(raw []string) []finding.ScannerName {
	out := make([]finding.ScannerName, 0, len(raw))
	for _, r := range raw {
		if r != "" {
			out = append(out, finding.ScannerName(r))
		}
	}
	return out
}

// reconcileAndReport folds the scan into the tracked state and prints what
// changed since last time — the only part of a scan a returning reader cares
// about.
func reconcileAndReport(
	cmd *cobra.Command,
	cfg *config.Config,
	logger ports.Logger,
	findings []finding.Finding,
	persist bool,
) error {
	reconcile := buildReconcile(cfg, logger)
	if reconcile == nil {
		return nil
	}

	resp, err := reconcile.Execute(cmd.Context(), dto.ReconcileRequest{
		Findings: findings,
		Persist:  persist,
	}).Get()
	if err != nil {
		return scannerErr(fmt.Sprintf("reconcile vulnerabilities: %v", err))
	}

	if resp.PersistError != nil {
		cmd.Printf("\nwarning: vulnerability state not saved: %v\n", resp.PersistError)
		cmd.Printf("  the scan results are unaffected; mount a writable path or pass --no-track\n")
	}

	r := resp.Result
	if resp.Known == 0 {
		cmd.Printf("\ntracking %d vulnerability(ies) - first scan, everything is new\n", len(r.All))
		return nil
	}

	cmd.Printf("\nsince the last scan: %d new, %d reopened, %d resolved",
		len(r.New), len(r.Reopened), len(r.Resolved))
	if len(r.Suppressed) > 0 {
		cmd.Printf(", %d suppressed by triage", len(r.Suppressed))
	}
	cmd.Println()

	for _, v := range r.Reopened {
		cmd.Printf("  regression: %s at %s:%d (fixed before, back again)\n",
			v.RuleID().String(), v.Location().File(), v.Location().StartLine())
	}
	return nil
}
