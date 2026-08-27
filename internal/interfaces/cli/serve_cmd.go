package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/interfaces/httpapi"
)

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run Cortex as a service clients connect to with an API key",
		Long: `Starts the HTTP API. Deploy this once — with the scanners installed, or
using the Docker image that carries them — and clients submit repositories
instead of installing seven tools in their own CI.

  POST /api/v1/analyses      {"repository": "github.com/org/repo", "ref": "main"}
  GET  /api/v1/analyses/{id}                 status, gate verdict, what is new
  GET  /api/v1/analyses/{id}/sarif           the findings
  POST /api/v1/scans                         ingest SARIF from a client's own CI
  GET|PUT /api/v1/projects/{p}/vulnerabilities   the tracked state

Every call except /healthz requires "Authorization: Bearer <api key>", and the
server refuses to start without at least one key configured: it can clone
repositories, so an open instance is not a sensible default.

Private repositories are cloned with the credentials in the server's own
environment (CORTEX_GIT_TOKEN, GITHUB_TOKEN, GITLAB_TOKEN, or an SSH agent) —
clients never send credentials over this API.`,
		Args: cobra.NoArgs,
	}

	cmd.Flags().String("addr", "", "listen address (default from server.addr)")
	cmd.Flags().String("data-dir", "", "where to keep analyses and state (default from server.data_dir)")
	cmd.Flags().Int("workers", 0, "concurrent analyses (default from server.workers)")

	cmd.RunE = runServe

	return cmd
}

func runServe(cmd *cobra.Command, _ []string) error {
	env, err := loadEnv(cmd)
	if err != nil {
		return err
	}

	applyServeOverrides(cmd, env)

	server, err := httpapi.New(env.cfg, env.logger)
	if err != nil {
		if errors.Is(err, httpapi.ErrNoAPIKeys) {
			return configErr(err.Error())
		}
		return configErr(fmt.Sprintf("start server: %v", err))
	}
	defer server.Close()

	httpServer := &http.Server{
		Addr:    env.cfg.Server.Addr,
		Handler: server.Handler(),
		// An analysis is asynchronous, so no request should be long-lived;
		// these ceilings exist to stop a stalled peer holding a connection.
		ReadHeaderTimeout: 15 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	env.logger.Info("cortex server listening",
		ports.F("addr", env.cfg.Server.Addr),
		ports.F("data_dir", env.cfg.Server.DataDir),
		ports.F("workers", fmt.Sprint(env.cfg.Server.Workers)),
		ports.F("api_keys", fmt.Sprint(server.Clients())))
	cmd.Printf("cortex serve on %s  •  data in %s  •  %d worker(s), %d API key(s)\n",
		env.cfg.Server.Addr, env.cfg.Server.DataDir,
		env.cfg.Server.Workers, server.Clients())

	return listenUntilSignal(cmd.Context(), httpServer, env.logger)
}

// applyServeOverrides lets flags win over the config file, so one image can
// serve several deployments without a config each.
func applyServeOverrides(cmd *cobra.Command, env cmdEnv) {
	if cmd.Flags().Changed("addr") {
		addr, _ := cmd.Flags().GetString("addr")
		env.cfg.Server.Addr = addr
	}
	if cmd.Flags().Changed("data-dir") {
		dir, _ := cmd.Flags().GetString("data-dir")
		env.cfg.Server.DataDir = dir
	}
	if cmd.Flags().Changed("workers") {
		workers, _ := cmd.Flags().GetInt("workers")
		env.cfg.Server.Workers = workers
	}
}

// listenUntilSignal serves until SIGINT or SIGTERM, then drains in-flight
// requests rather than cutting them: a client polling an analysis should not
// get a reset because the box was redeployed.
func listenUntilSignal(
	ctx context.Context, server *http.Server, logger ports.Logger,
) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errs := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			errs <- err
			return
		}
		errs <- nil
	}()

	select {
	case err := <-errs:
		if err != nil {
			return scannerErr(fmt.Sprintf("listen on %s: %v", server.Addr, err))
		}
		return nil
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return scannerErr(fmt.Sprintf("shutdown: %v", err))
		}
		return nil
	}
}
