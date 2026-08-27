package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/vulnerability"
	"github.com/vektcore/cortex/internal/infrastructure/config"
	gitinfra "github.com/vektcore/cortex/internal/infrastructure/git"
)

// timeNow is a seam for tests; production always reads the wall clock.
var timeNow = time.Now

// narrowGateScope reduces what the Quality Gate judges.
//
// An absolute gate ("zero criticals") is unadoptable for a repository that
// already carries thousands of findings: it fails on day one, forever, and the
// team turns it off. A gate on *new* code is adoptable today and still drives
// the debt down, because every change either keeps it flat or reduces it.
//
// Two definitions of "new" are supported, and they answer different questions:
//
//	--new-only            new to the tracked state — never seen in any scan
//	--changed-since REF   sitting on a line this branch touched
//
// Combined, they intersect: new weaknesses introduced by this branch.
//
// Suppression by triage is always applied, with or without either flag: a
// decision somebody recorded is not re-litigated on every run.
func narrowGateScope(
	cmd *cobra.Command,
	cfg *config.Config,
	findings []finding.Finding,
	newOnly bool,
	changedSince string,
) ([]finding.Finding, error) {
	out := findings

	if store := buildStore(cfg); store != nil {
		stored, err := store.Load(cmd.Context()).Get()
		if err != nil {
			return nil, configErr(err.Error())
		}

		now := timeNow()
		before := len(out)
		out = vulnerability.OpenFindingsGate(stored, out, now)
		if suppressed := before - len(out); suppressed > 0 {
			cmd.Printf("gate: %d finding(s) suppressed by triage\n", suppressed)
		}

		if newOnly {
			result := vulnerability.Reconcile(stored, out, now)
			out = findingsOf(result.New, result.Reopened, out)
			cmd.Printf("gate: new code only — %d of %d finding(s) are new or regressions\n",
				len(out), len(findings))
		}
	} else if newOnly {
		return nil, configErr(
			"--new-only needs vulnerability tracking (state.enabled: true)")
	}

	if changedSince != "" {
		changed, err := gitinfra.New().ChangedLines(cmd.Context(), ".", changedSince).Get()
		if err != nil {
			return nil, configErr(fmt.Sprintf("--changed-since %s: %v", changedSince, err))
		}

		ranges := make(map[string][]finding.LineRange, len(changed))
		for file, hunks := range changed {
			for _, h := range hunks {
				ranges[file] = append(ranges[file], finding.LineRange{Start: h.Start, End: h.End})
			}
		}

		before := len(out)
		out = finding.OnLines(out, ranges)
		cmd.Printf("gate: changed lines vs %s — %d of %d finding(s) are on touched lines\n",
			changedSince, len(out), before)
	}

	return out, nil
}

// findingsOf maps the vulnerabilities the reconciliation classified as new or
// reopened back to the findings of this scan, matching on identity.
func findingsOf(
	newVulns, reopened []vulnerability.Vulnerability, findings []finding.Finding,
) []finding.Finding {
	keys := make(map[finding.Fingerprint]struct{}, len(newVulns)+len(reopened))
	for _, v := range newVulns {
		keys[v.Identity().Exact] = struct{}{}
	}
	for _, v := range reopened {
		keys[v.Identity().Exact] = struct{}{}
	}

	out := make([]finding.Finding, 0, len(keys))
	for _, f := range findings {
		if _, ok := keys[f.Fingerprint()]; ok {
			out = append(out, f)
		}
	}
	return out
}
