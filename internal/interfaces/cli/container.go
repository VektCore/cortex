package cli

import (
	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/application/services"
	"github.com/vektcore/cortex/internal/application/usecases"
	"github.com/vektcore/cortex/internal/bootstrap"
	"github.com/vektcore/cortex/internal/infrastructure/config"
	"github.com/vektcore/cortex/internal/infrastructure/scanners"
)

// The object graph itself lives in internal/bootstrap, because the HTTP server
// needs the same one. What stays here is the CLI's own concern: turning a
// failure into the exit code CI reads.

// exitError carries a specific exit code from a command RunE back to Execute.
type exitError struct {
	code int
	msg  string
}

func (e exitError) Error() string { return e.msg }
func (e exitError) ExitCode() int { return e.code }

// helpers to create typed exit errors
func gateFailedErr(msg string) error { return exitError{ExitGateFailed, msg} }
func configErr(msg string) error     { return exitError{ExitConfigError, msg} }
func scannerErr(msg string) error    { return exitError{ExitScannerError, msg} }

type randomIDGen = bootstrap.RandomIDGen

func buildLogger(level string, quiet bool) ports.Logger {
	return bootstrap.Logger(level, quiet)
}

func buildRegistry(cfg *config.Config, codec ports.SarifCodec) *scanners.Registry {
	return bootstrap.Registry(cfg, codec)
}

func buildExecuteScan(
	cfg *config.Config, codec ports.SarifCodec, logger ports.Logger,
) *usecases.ExecuteScan {
	return bootstrap.ExecuteScan(cfg, codec, logger)
}

func buildStore(cfg *config.Config) ports.VulnerabilityStore {
	return bootstrap.Store(cfg)
}

func buildReconcile(
	cfg *config.Config, logger ports.Logger,
) *usecases.ReconcileVulnerabilities {
	return bootstrap.Reconcile(cfg, logger)
}

func buildDetector() ports.LanguageDetector { return bootstrap.Detector() }

func buildPipeline(cfg *config.Config, logger ports.Logger) *services.Pipeline {
	return bootstrap.Pipeline(cfg, logger)
}

func buildPublishResults(
	cfg *config.Config, logger ports.Logger,
) *usecases.PublishResults {
	return bootstrap.PublishResults(cfg, logger)
}
