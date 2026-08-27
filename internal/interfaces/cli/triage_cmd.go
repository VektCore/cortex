package cli

import (
	"fmt"
	"os"
	"os/user"
	"time"

	"github.com/samber/mo"
	"github.com/spf13/cobra"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/application/usecases"
	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/domain/vulnerability"
)

func newTriageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "triage <fingerprint>",
		Short: "Record a decision about a vulnerability so the next scan does not ask again",
		Long: `Marks a tracked vulnerability as confirmed, a false positive, or an accepted
risk. The decision is stored against the vulnerability's identity, not against a
line number, so it survives the code being edited or the function being moved.

A reason is mandatory. An accepted risk without --expires is refused: an
exception nobody revisits is how a finding disappears for good.

  cortex triage a1b2c3d4 --status false_positive --reason "test fixture, not shipped"
  cortex triage a1b2c3d4 --status accepted_risk  --reason "legacy, migrating in Q4" --expires 2026-12-31
  cortex triage a1b2c3d4 --status confirmed      --reason "real, ticket SEC-412"`,
		Args: cobra.ExactArgs(1),
	}
	cmd.Flags().String("status", "",
		"confirmed | false_positive | accepted_risk")
	cmd.Flags().String("reason", "", "why (required)")
	cmd.Flags().String("author", "", "who decided (defaults to the current user)")
	cmd.Flags().String("expires", "", "YYYY-MM-DD; required for accepted_risk")

	cmd.RunE = runTriage

	return cmd
}

func runTriage(cmd *cobra.Command, args []string) error {
	decision, err := triageFlags(cmd)
	if err != nil {
		return err
	}

	env, err := loadEnv(cmd)
	if err != nil {
		return err
	}

	store := buildStore(env.cfg)
	if store == nil {
		return configErr("vulnerability tracking is disabled (state.enabled: false)")
	}

	resp, execErr := usecases.NewTriageVulnerability(usecases.TriageDeps{
		Store:  store,
		Clock:  shared.SystemClock{},
		Logger: env.logger,
	}).Execute(cmd.Context(), dto.TriageRequest{
		Key:     args[0],
		Status:  decision.status,
		Reason:  decision.reason,
		Author:  decision.author,
		Expires: decision.expires,
	}).Get()
	if execErr != nil {
		return configErr(execErr.Error())
	}

	v := resp.Vulnerability
	cmd.Printf("%s  %s → %s\n", v.Key().String()[:8], v.RuleID().String(), v.Status().String())
	cmd.Printf("  %s:%d\n", v.Location().File(), v.Location().StartLine())
	if deadline, ok := decision.expires.Get(); ok {
		cmd.Printf("  expires %s\n", deadline.Format("2006-01-02"))
	}
	return nil
}

// triageDecision is the validated form of the command's flags.
type triageDecision struct {
	status  vulnerability.Status
	reason  string
	author  string
	expires mo.Option[time.Time]
}

// triageFlags validates the flags. Every rule here exists to keep the audit
// trail meaningful: a decision without a reason, or an indefinite exception, is
// how a finding disappears without anybody deciding it should.
func triageFlags(cmd *cobra.Command) (triageDecision, error) {
	rawStatus, _ := cmd.Flags().GetString("status")
	reason, _ := cmd.Flags().GetString("reason")
	author, _ := cmd.Flags().GetString("author")
	rawExpires, _ := cmd.Flags().GetString("expires")

	status, err := vulnerability.ParseStatus(rawStatus).Get()
	if err != nil || !status.Triaged() {
		return triageDecision{}, configErr(fmt.Sprintf(
			"--status must be confirmed, false_positive or accepted_risk (got %q)", rawStatus))
	}
	if reason == "" {
		return triageDecision{}, configErr(
			"--reason is required: an unexplained suppression is indistinguishable from a mistake")
	}

	expires, err := parseExpiry(rawExpires, status)
	if err != nil {
		return triageDecision{}, configErr(err.Error())
	}

	return triageDecision{
		status:  status,
		reason:  reason,
		author:  resolveAuthor(author),
		expires: expires,
	}, nil
}

// parseExpiry reads the deadline and enforces that an accepted risk carries one.
func parseExpiry(raw string, status vulnerability.Status) (mo.Option[time.Time], error) {
	if raw == "" {
		if status == vulnerability.StatusAcceptedRisk {
			return mo.None[time.Time](), fmt.Errorf(
				"--expires is required for accepted_risk: an exception with no end date is never revisited")
		}
		return mo.None[time.Time](), nil
	}

	deadline, err := time.Parse("2006-01-02", raw)
	if err != nil {
		return mo.None[time.Time](), fmt.Errorf("--expires must be YYYY-MM-DD: %w", err)
	}
	// End of the given day, so "expires today" still suppresses today.
	deadline = deadline.Add(24*time.Hour - time.Second)
	if deadline.Before(time.Now()) {
		return mo.None[time.Time](), fmt.Errorf("--expires %s is in the past", raw)
	}
	return shared.Some(deadline), nil
}

// resolveAuthor falls back to the environment so the audit trail is never
// anonymous by accident.
func resolveAuthor(explicit string) string {
	if explicit != "" {
		return explicit
	}
	for _, env := range []string{"CORTEX_AUTHOR", "GITHUB_ACTOR", "USER"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "unknown"
}
