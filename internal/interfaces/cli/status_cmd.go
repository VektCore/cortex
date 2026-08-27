package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/vektcore/cortex/internal/domain/vulnerability"
	"github.com/vektcore/cortex/internal/infrastructure/config"
)

func newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the tracked vulnerability state: open, triaged, resolved, regressions",
		Long: `Reads the vulnerability state and summarises it. This is the view that a
list of findings cannot give: how old the debt is, what came back after being
fixed, and how much of it somebody has actually judged.`,
		Args: cobra.NoArgs,
	}
	cmd.Flags().Bool("json", false, "machine-readable output")
	cmd.Flags().Int("oldest", 5, "how many of the oldest open vulnerabilities to list")

	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		asJSON, _ := cmd.Flags().GetBool("json")
		oldest, _ := cmd.Flags().GetInt("oldest")
		cfgPath, _ := cmd.Root().PersistentFlags().GetString("config")

		cfg, err := config.Load(cfgPath)
		if err != nil {
			return configErr(fmt.Sprintf("load config: %v", err))
		}

		store := buildStore(cfg)
		if store == nil {
			return configErr("vulnerability tracking is disabled (state.enabled: false)")
		}

		stored, loadErr := store.Load(cmd.Context()).Get()
		if loadErr != nil {
			return configErr(loadErr.Error())
		}

		summary := summarize(stored, time.Now())

		if asJSON {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return renderErr(enc.Encode(summary))
		}

		printStatus(cmd, summary, stored, oldest)
		return nil
	}

	return cmd
}

// statusSummary is the machine-readable shape of the state.
type statusSummary struct {
	Total       int            `json:"total"`
	Open        int            `json:"open"`
	Suppressed  int            `json:"suppressed"`
	Resolved    int            `json:"resolved"`
	Regressions int            `json:"regressions"`
	Untriaged   int            `json:"untriaged"`
	ExpiredExc  int            `json:"expired_exceptions"`
	ByStatus    map[string]int `json:"by_status"`
	BySeverity  map[string]int `json:"by_severity_open"`
	OldestDays  int            `json:"oldest_open_days"`
}

func summarize(stored []vulnerability.Vulnerability, now time.Time) statusSummary {
	out := statusSummary{
		Total:      len(stored),
		ByStatus:   make(map[string]int),
		BySeverity: make(map[string]int),
	}

	for _, v := range stored {
		out.ByStatus[v.Status().String()]++

		switch {
		case v.Status() == vulnerability.StatusResolved:
			out.Resolved++
		case v.SuppressedAt(now):
			out.Suppressed++
		default:
			out.Open++
			out.BySeverity[v.Severity().String()]++
			if !v.Status().Triaged() {
				out.Untriaged++
			}
			if days := int(v.Age(now).Hours() / 24); days > out.OldestDays {
				out.OldestDays = days
			}
		}

		if v.ReopenCount() > 0 {
			out.Regressions++
		}
		// An exception that ran out is worse than no exception: somebody
		// believed it was covered.
		if t, ok := v.TriageDecision().Get(); ok && t.Expired(now) && t.Status().Suppressed() {
			out.ExpiredExc++
		}
	}
	return out
}

func printStatus(
	cmd *cobra.Command, s statusSummary, stored []vulnerability.Vulnerability, oldest int,
) {
	cmd.Printf("Vulnerability state: %d tracked\n\n", s.Total)
	cmd.Printf("  open          %d\n", s.Open)
	cmd.Printf("  suppressed    %d  (false positive / accepted risk)\n", s.Suppressed)
	cmd.Printf("  resolved      %d\n", s.Resolved)

	if s.Open > 0 {
		cmd.Printf("\nOpen by severity:\n")
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if n := s.BySeverity[sev]; n > 0 {
				cmd.Printf("  %-10s %d\n", sev, n)
			}
		}
		cmd.Printf("\n  untriaged     %d of %d open\n", s.Untriaged, s.Open)
		cmd.Printf("  oldest open   %d days\n", s.OldestDays)
	}

	if s.Regressions > 0 {
		cmd.Printf("\n⚠  %d vulnerability(ies) came back after being resolved\n", s.Regressions)
	}
	if s.ExpiredExc > 0 {
		cmd.Printf("⚠  %d exception(s) have expired and no longer suppress anything\n", s.ExpiredExc)
	}

	printOldest(cmd, stored, oldest)
}

// printOldest lists the open vulnerabilities that have been known longest —
// the ones a "we'll fix it later" turned into permanent debt.
func printOldest(cmd *cobra.Command, stored []vulnerability.Vulnerability, limit int) {
	if limit <= 0 {
		return
	}

	now := time.Now()
	open := make([]vulnerability.Vulnerability, 0, len(stored))
	for _, v := range stored {
		if v.Status().Open() && !v.SuppressedAt(now) {
			open = append(open, v)
		}
	}
	if len(open) == 0 {
		return
	}

	sort.Slice(open, func(i, j int) bool {
		if open[i].Severity() != open[j].Severity() {
			return open[i].Severity() > open[j].Severity()
		}
		return open[i].FirstSeen().Before(open[j].FirstSeen())
	})
	if len(open) > limit {
		open = open[:limit]
	}

	cmd.Printf("\nOldest open, worst first:\n")
	for _, v := range open {
		cwe := "—"
		if c, ok := v.CWE().Get(); ok {
			cwe = c.String()
		}
		cmd.Printf("  %-8s %-10s %-9s %s:%d  %s  (%dd, seen %dx)\n",
			v.Key().String()[:8],
			v.Severity().String(),
			cwe,
			v.Location().File(),
			v.Location().StartLine(),
			v.RuleID().String(),
			int(v.Age(now).Hours()/24),
			v.TimesSeen(),
		)
	}
	cmd.Printf("\nTriage one with: cortex triage <fingerprint> --status false_positive --reason \"…\"\n")
}
