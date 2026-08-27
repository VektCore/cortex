package cli

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/infrastructure/config"
	infrasarif "github.com/vektcore/cortex/internal/infrastructure/sarif"
)

func newDetectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detect [path]",
		Short: "Detect languages and applicable scanners in the target path",
		Long: `Walks the target directory and reports which programming languages are
present and which configured scanners apply to each, flagging the ones whose
binary is not installed. Useful as a dry-run before scan/pipeline.`,
		Args: cobra.MaximumNArgs(1),
	}
	cmd.Flags().StringSlice("exclude", nil, "path fragments to skip during detection")
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

		exclude, _ := cmd.Flags().GetStringSlice("exclude")
		cfgPath, _ := cmd.Root().PersistentFlags().GetString("config")

		cfg, err := config.Load(cfgPath)
		if err != nil {
			return configErr(fmt.Sprintf("load config: %v", err))
		}

		exclude = append(cfg.ExcludePatterns(), exclude...)

		languages, detErr := buildDetector().Detect(cmd.Context(), targetPath, exclude).Get()
		if detErr != nil {
			return scannerErr(fmt.Sprintf("detect: %v", detErr))
		}

		if len(languages) == 0 {
			cmd.Printf("detect: no supported language found in %s\n", targetPath)
			return nil
		}

		reg := buildRegistry(cfg, infrasarif.New())

		cmd.Printf("detect: %s\n\n", targetPath)
		for _, lang := range sortedLanguages(languages) {
			cmd.Printf("  %-12s %s\n", lang.String(), describeScanners(cmd, reg, lang))
		}

		cmd.Printf("\nlanguages: %d   scanners enabled: %d\n", len(languages), len(reg.All()))
		return nil
	}

	return cmd
}

// describeScanners lists the enabled scanners for one language, marking those
// whose binary is missing from PATH.
func describeScanners(cmd *cobra.Command, reg ports.ScannerRegistry, lang shared.Language) string {
	applicable := reg.ForLanguage(lang)
	if len(applicable) == 0 {
		return "(no scanner enabled)"
	}

	names := make([]string, 0, len(applicable))
	for _, sc := range applicable {
		name := string(sc.Name())
		if !sc.Available(cmd.Context()) {
			name += " [not installed]"
		}
		names = append(names, name)
	}
	sort.Strings(names)

	out := ""
	for i, n := range names {
		if i > 0 {
			out += " · "
		}
		out += n
	}
	return out
}

func sortedLanguages(langs []shared.Language) []shared.Language {
	out := append([]shared.Language(nil), langs...)
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
