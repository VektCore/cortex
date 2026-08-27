// Package cli is the primary adapter that exposes Cortex as a command-line tool.
//
// Responsibilities:
//   - Parse flags and config (via cobra/viper).
//   - Translate CLI inputs into application use-case requests.
//   - Map use-case results to exit codes and human-readable output.
//
// It must NEVER contain business logic — only translation between the CLI
// boundary and the application layer.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// Build-time injected metadata (see Makefile LDFLAGS).
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

// Exit codes are part of the public contract with CI systems.
const (
	ExitOK             = 0
	ExitGateFailed     = 1
	ExitConfigError    = 2
	ExitScannerError   = 3
	ExitPublisherError = 4
	ExitInternalError  = 99
)

// Execute is the single entrypoint invoked from main.
// It returns an exit code — never panics, never calls os.Exit directly.
func Execute(ctx context.Context, args []string) int {
	root := newRootCmd(os.Stdout, os.Stderr)
	root.SetArgs(args)

	if err := root.ExecuteContext(ctx); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "cortex: %v\n", err)
		var ee exitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		return ExitInternalError
	}
	return ExitOK
}

func newRootCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "cortex",
		Short:         "Multi-language SAST engine for CI/CD pipelines",
		Long:          longDescription,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       fmt.Sprintf("%s (commit %s, built %s)", version, commit, buildDate),
	}
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	cmd.PersistentFlags().StringP("config", "c", ".cortex.yaml",
		"path to cortex configuration file")
	cmd.PersistentFlags().StringP("log-level", "l", "info",
		"log level: debug, info, warn, error")
	cmd.PersistentFlags().Bool("quiet", false, "suppress non-essential output")

	cmd.AddCommand(
		newDetectCmd(),
		newScanCmd(),
		newAggregateCmd(),
		newVerifyCmd(),
		newReportCmd(),
		newPublishCmd(),
		newBaselineCmd(),
		newPipelineCmd(),
		newServeCmd(),
		newStatusCmd(),
		newTriageCmd(),
		newVersionCmd(),
	)

	return cmd
}

const longDescription = `Cortex runs multiple SAST scanners in parallel, aggregates
their findings into a single SARIF report, applies a declarative Quality Gate,
and publishes results to one or more destinations (KorvLabs, GitHub Code
Scanning, Slack, etc.).

It is designed to act as a single step inside any CI/CD pipeline, returning
exit codes that gate merges based on configurable severity thresholds.

Workflow:
  cortex detect      → discover languages and applicable scanners
  cortex scan        → run all configured scanners in parallel
  cortex aggregate   → merge SARIF files, deduplicate findings
  cortex verify      → apply Quality Gate (returns non-zero on failure)
  cortex report      → render human-readable summary
  cortex publish     → send results to configured destinations
  cortex pipeline    → run the full chain in one shot

Server mode (clients connect with an API key instead of installing scanners):
  cortex serve       → HTTP API: submit a repository, poll the analysis

Vulnerability tracking (state kept between scans):
  cortex status      → open / triaged / resolved, regressions, oldest debt
  cortex triage      → confirm, dismiss or accept a vulnerability

See https://github.com/vektcore/cortex for documentation.`
