package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/application/usecases"
	"github.com/vektcore/cortex/internal/domain/finding"
	infrasarif "github.com/vektcore/cortex/internal/infrastructure/sarif"
)

func newAggregateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aggregate <sarif-files...>",
		Short: "Merge SARIF files and deduplicate findings",
		Long: `Merges several SARIF documents — typically one per scanner — into a single
document, dropping duplicate findings. Two findings are duplicates when their
fingerprints match (same rule, file, lines and normalized snippet); the highest
severity wins.`,
		Args: cobra.MinimumNArgs(1),
	}
	cmd.Flags().String("output", "results/merged.sarif", "merged SARIF output path")
	cmd.Flags().Bool("raw", false,
		"concatenate the original SARIF runs instead of re-emitting deduplicated findings")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		outPath, _ := cmd.Flags().GetString("output")
		raw, _ := cmd.Flags().GetBool("raw")

		codec := infrasarif.New()

		docs := make([][]byte, 0, len(args))
		batches := make([][]finding.Finding, 0, len(args))
		total := 0
		for _, path := range args {
			findings, data, err := readSARIF(codec, path)
			if err != nil {
				return configErr(err.Error())
			}
			docs = append(docs, data)
			batches = append(batches, findings)
			total += len(findings)
			cmd.Printf("  %-40s %d finding(s)\n", path, len(findings))
		}

		merged, err := mergedDocument(codec, docs, batches, raw)
		if err != nil {
			return scannerErr(err.Error())
		}

		if mkErr := os.MkdirAll(filepath.Dir(outPath), 0o755); mkErr != nil {
			return scannerErr(fmt.Sprintf("create output dir: %v", mkErr))
		}
		if wErr := os.WriteFile(outPath, merged, 0o600); wErr != nil {
			return scannerErr(fmt.Sprintf("write %q: %v", outPath, wErr))
		}

		deduped := usecases.NewAggregateFindings().Execute(
			dto.AggregateFindingsRequest{Inputs: batches},
		).Findings

		cmd.Printf("\naggregate: %d → %d finding(s) after dedup  →  %s\n",
			total, len(deduped), outPath)
		return nil
	}

	return cmd
}

// mergedDocument produces the output document: either the raw concatenation of
// the input runs, or a canonical Cortex document holding deduplicated findings.
func mergedDocument(
	codec ports.SarifCodec,
	docs [][]byte,
	batches [][]finding.Finding,
	raw bool,
) ([]byte, error) {
	if raw {
		out, err := codec.Merge(docs).Get()
		if err != nil {
			return nil, fmt.Errorf("merge SARIF: %w", err)
		}
		return out, nil
	}

	deduped := usecases.NewAggregateFindings().Execute(
		dto.AggregateFindingsRequest{Inputs: batches},
	).Findings

	out, err := codec.Write(deduped, ports.SarifMetadata{
		Tool:    "cortex",
		Version: version,
	}).Get()
	if err != nil {
		return nil, fmt.Errorf("write merged SARIF: %w", err)
	}
	return out, nil
}
