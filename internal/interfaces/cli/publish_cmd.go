package cli

import (
	"context"
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/domain/scan"
	"github.com/vektcore/cortex/internal/infrastructure/config"
	gitinfra "github.com/vektcore/cortex/internal/infrastructure/git"
	infrasarif "github.com/vektcore/cortex/internal/infrastructure/sarif"
)

func newPublishCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "publish [sarif-file]",
		Short: "Send results to configured publishers",
		Long: `Ships an existing SARIF document to every publisher enabled in .cortex.yaml
(or the subset named with --to). Publisher failures are reported individually
and produce exit code 4.`,
		Args: cobra.MaximumNArgs(1),
	}
	cmd.Flags().StringSlice("to", nil, "subset of publishers to use (default: all enabled)")
	cmd.Flags().String("repo", ".", "repository path used to resolve the git revision")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		sarifFile := "results/scan.sarif"
		if len(args) > 0 {
			sarifFile = args[0]
		}

		targets, _ := cmd.Flags().GetStringSlice("to")
		repoPath, _ := cmd.Flags().GetString("repo")
		cfgPath, _ := cmd.Root().PersistentFlags().GetString("config")
		logLevel, _ := cmd.Root().PersistentFlags().GetString("log-level")
		quiet, _ := cmd.Root().PersistentFlags().GetBool("quiet")

		cfg, err := config.Load(cfgPath)
		if err != nil {
			return configErr(fmt.Sprintf("load config: %v", err))
		}

		codec := infrasarif.New()
		findings, raw, err := readEnrichedSARIF(codec, sarifFile, cfg)
		if err != nil {
			return configErr(err.Error())
		}

		logger := buildLogger(logLevel, quiet)
		s := scan.New(randomIDGen{}.NewScanID(), currentRevision(cmd.Context(), repoPath))

		resp := buildPublishResults(cfg, logger).Execute(cmd.Context(), dto.PublishResultsRequest{
			Scan:     s,
			Findings: findings,
			SARIF:    raw,
			Targets:  targets,
		})

		for _, r := range resp.Receipts {
			cmd.Printf("  %-20s ok  %s\n", r.Publisher, r.Reference)
		}

		if len(resp.Errors) == 0 {
			cmd.Printf("\npublish: %d finding(s) sent to %d publisher(s)\n",
				len(findings), len(resp.Receipts))
			return nil
		}

		names := make([]string, 0, len(resp.Errors))
		for name := range resp.Errors {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			cmd.Printf("  %-20s FAILED  %v\n", name, resp.Errors[name])
		}
		return exitError{ExitPublisherError, fmt.Sprintf("%d publisher(s) failed", len(names))}
	}

	return cmd
}

// currentRevision resolves the git revision of repoPath, degrading to
// scan.UnknownRevision() outside a repository.
func currentRevision(ctx context.Context, repoPath string) scan.Revision {
	rev, err := gitinfra.New().CurrentRevision(ctx, repoPath).Get()
	if err != nil {
		return scan.UnknownRevision()
	}
	return rev
}
