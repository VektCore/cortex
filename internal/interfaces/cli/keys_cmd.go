package cli

import (
	"fmt"
	"math"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/vektcore/cortex/internal/infrastructure/apikeys"
)

func newKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Issue, list and revoke the API keys clients authenticate with",
		Long: `Manages the credentials 'cortex serve' accepts.

One key per client, each with an expiry. The secret is shown once at issue and
never stored — only its SHA-256 — so a lost key is replaced, never recovered,
and a leaked database hands over nobody's credential.

Keys live wherever server.database points: PostgreSQL when a DSN is set, and
otherwise a file under server.data_dir. Run this against the same configuration
the server uses, or the key lands in a store the server does not read.

  cortex keys issue --client acme --ttl 90d
  cortex keys list
  cortex keys revoke 3f9a2c1d`,
	}

	cmd.AddCommand(newKeysIssueCmd(), newKeysListCmd(), newKeysRevokeCmd())
	return cmd
}

func newKeysIssueCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "issue",
		Short: "Mint a key for one client",
		Args:  cobra.NoArgs,
		RunE:  runKeysIssue,
	}
	cmd.Flags().String("client", "", "who the key belongs to (required)")
	cmd.Flags().String("ttl", "", "lifetime, e.g. 90d, 12h (default from server.api_key_ttl)")
	return cmd
}

func runKeysIssue(cmd *cobra.Command, _ []string) error {
	env, err := loadEnv(cmd)
	if err != nil {
		return err
	}

	client, _ := cmd.Flags().GetString("client")
	if client == "" {
		return configErr("--client is required: a key that names nobody cannot be audited")
	}

	ttl, err := resolveTTL(cmd, env)
	if err != nil {
		return configErr(err.Error())
	}

	repo, err := openKeys(cmd, env)
	if err != nil {
		return err
	}
	defer repo.Close()

	key, secret, err := repo.Issue(cmd.Context(), client, ttl, time.Now())
	if err != nil {
		return scannerErr(fmt.Sprintf("issue key: %v", err))
	}

	cmd.Printf("key issued for %s\n\n", key.Client)
	cmd.Printf("  id         %s\n", key.ID)
	cmd.Printf("  expires    %s  (in %d days)\n",
		key.ExpiresAt.Format(time.RFC3339), daysUntil(key.ExpiresAt))
	cmd.Printf("\n  %s\n\n", secret)
	// Said plainly because it is the one irreversible moment in this command.
	cmd.Printf("This is the only time the secret is shown. It is stored as a\n")
	cmd.Printf("hash, so it cannot be recovered — only revoked and reissued.\n")
	return nil
}

func newKeysListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show every key, newest first",
		Args:  cobra.NoArgs,
		RunE:  runKeysList,
	}
}

func runKeysList(cmd *cobra.Command, _ []string) error {
	env, err := loadEnv(cmd)
	if err != nil {
		return err
	}

	repo, err := openKeys(cmd, env)
	if err != nil {
		return err
	}
	defer repo.Close()

	keys, err := repo.List(cmd.Context())
	if err != nil {
		return scannerErr(fmt.Sprintf("list keys: %v", err))
	}
	if len(keys) == 0 {
		cmd.Println("no keys issued yet — cortex keys issue --client <name>")
		return nil
	}

	now := time.Now()
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tCLIENT\tSTATUS\tENDS\tSECRET")
	for _, k := range keys {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t…%s\n",
			k.ID, k.Client, k.Status(now),
			k.ExpiresAt.Format("2006-01-02"), k.Hint)
	}
	return w.Flush()
}

func newKeysRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <id>",
		Short: "Stop a key working now, without waiting for its expiry",
		Args:  cobra.ExactArgs(1),
		RunE:  runKeysRevoke,
	}
}

func runKeysRevoke(cmd *cobra.Command, args []string) error {
	env, err := loadEnv(cmd)
	if err != nil {
		return err
	}

	repo, err := openKeys(cmd, env)
	if err != nil {
		return err
	}
	defer repo.Close()

	key, err := repo.Revoke(cmd.Context(), args[0], time.Now())
	if err != nil {
		return configErr(fmt.Sprintf("revoke key: %v", err))
	}

	cmd.Printf("key %s (%s) revoked — it stops authenticating immediately\n",
		key.ID, key.Client)
	return nil
}

// openKeys resolves the same store the server would, so a key is never issued
// somewhere the server does not look.
func openKeys(cmd *cobra.Command, env cmdEnv) (apikeys.Repository, error) {
	repo, err := apikeys.Open(cmd.Context(), env.cfg.Server.Database, env.cfg.Server.DataDir)
	if err != nil {
		return nil, configErr(fmt.Sprintf("open key store: %v", err))
	}
	return repo, nil
}

func resolveTTL(cmd *cobra.Command, env cmdEnv) (time.Duration, error) {
	raw, _ := cmd.Flags().GetString("ttl")
	if raw == "" {
		raw = env.cfg.Server.APIKeyTTL
	}
	if raw == "" {
		raw = "90d"
	}
	return apikeys.ParseTTL(raw)
}

// daysUntil rounds rather than truncates: a key issued for 45d is reported as
// 45 days, not 44 because a second has already passed.
func daysUntil(t time.Time) int {
	days := int(math.Round(time.Until(t).Hours() / 24))
	if days < 0 {
		return 0
	}
	return days
}
