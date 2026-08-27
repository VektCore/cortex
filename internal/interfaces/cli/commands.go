package cli

import (
	"github.com/spf13/cobra"
)

// Command constructors that are small enough to live together. The larger
// ones have their own file: scan_cmd.go, verify_cmd.go, pipeline_cmd.go,
// detect_cmd.go, aggregate_cmd.go, report_cmd.go, publish_cmd.go,
// baseline_cmd.go.

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Printf("cortex %s\ncommit:     %s\nbuilt:      %s\n",
				version, commit, buildDate)
		},
	}
}
