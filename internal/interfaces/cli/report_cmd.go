package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/gate"
	"github.com/vektcore/cortex/internal/domain/scan"
	"github.com/vektcore/cortex/internal/infrastructure/config"
	"github.com/vektcore/cortex/internal/infrastructure/reporters/markdown"
	infrasarif "github.com/vektcore/cortex/internal/infrastructure/sarif"
)

func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report [sarif-file]",
		Short: "Render a human-readable report (markdown, json, text)",
		Long: `Renders a SARIF document as a report. This command never evaluates the
Quality Gate — use "cortex verify" for that — so it always exits 0.`,
		Args: cobra.MaximumNArgs(1),
	}
	cmd.Flags().String("format", "markdown", "output format: markdown, json, text")
	cmd.Flags().String("output", "-", "output file (- for stdout)")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		sarifFile := "results/scan.sarif"
		if len(args) > 0 {
			sarifFile = args[0]
		}

		format, _ := cmd.Flags().GetString("format")
		outPath, _ := cmd.Flags().GetString("output")

		cfgPath, _ := cmd.Root().PersistentFlags().GetString("config")
		cfg, cfgErr := config.Load(cfgPath)
		if cfgErr != nil {
			return configErr(fmt.Sprintf("load config: %v", cfgErr))
		}

		findings, _, err := readEnrichedSARIF(infrasarif.New(), sarifFile, cfg)
		if err != nil {
			return configErr(err.Error())
		}

		w, closeFn, err := openOutput(cmd.OutOrStdout(), outPath)
		if err != nil {
			return scannerErr(err.Error())
		}
		defer closeFn()

		switch format {
		case "markdown", "md":
			return renderErr(markdown.New().Report(w, scan.Scan{}, findings, gate.Pass()))
		case "json":
			return renderErr(renderJSON(w, findings))
		case "text", "txt":
			return renderErr(renderText(w, findings))
		default:
			return configErr(fmt.Sprintf("unknown format %q (use markdown, json or text)", format))
		}
	}

	return cmd
}

func renderErr(err error) error {
	if err != nil {
		return scannerErr(fmt.Sprintf("render report: %v", err))
	}
	return nil
}

// openOutput resolves "-" to the command's stdout and any other value to a
// file. The returned closer is always safe to call.
func openOutput(stdout io.Writer, path string) (io.Writer, func(), error) {
	if path == "" || path == "-" {
		return stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, func() {}, fmt.Errorf("create %q: %w", path, err)
	}
	return f, func() { _ = f.Close() }, nil
}

// jsonFinding is the flat serialization form. It exists so the JSON contract
// is explicit and independent of the domain's unexported fields.
type jsonFinding struct {
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	CWE         string `json:"cwe,omitempty"`
	File        string `json:"file"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	Message     string `json:"message"`
	Scanner     string `json:"scanner"`
}

type jsonReport struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	Findings   []jsonFinding  `json:"findings"`
}

func renderJSON(w io.Writer, findings []finding.Finding) error {
	items := make([]jsonFinding, 0, len(findings))
	for _, f := range findings {
		item := jsonFinding{
			Fingerprint: f.Fingerprint().String(),
			RuleID:      f.RuleID().String(),
			Severity:    f.Severity().String(),
			File:        f.Location().File(),
			StartLine:   f.Location().StartLine(),
			EndLine:     f.Location().EndLine(),
			Message:     f.Message().String(),
			Scanner:     string(f.Source()),
		}
		if cwe, ok := f.CWE().Get(); ok {
			item.CWE = cwe.String()
		}
		items = append(items, item)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonReport{
		Total:      len(findings),
		BySeverity: countBySeverity(findings),
		Findings:   items,
	})
}

func renderText(w io.Writer, findings []finding.Finding) error {
	counts := countBySeverity(findings)
	severities := make([]string, 0, len(counts))
	for sev := range counts {
		severities = append(severities, sev)
	}
	sort.Strings(severities)

	if _, err := fmt.Fprintf(w, "cortex report: %d finding(s)\n", len(findings)); err != nil {
		return err
	}
	for _, sev := range severities {
		if _, err := fmt.Fprintf(w, "  %-10s %d\n", sev, counts[sev]); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	for _, f := range findings {
		if _, err := fmt.Fprintf(w, "%-10s %s:%d  %s  (%s)\n",
			f.Severity().String(),
			f.Location().File(),
			f.Location().StartLine(),
			f.RuleID().String(),
			f.Source(),
		); err != nil {
			return err
		}
	}
	return nil
}
