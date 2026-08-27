package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/gate"
	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/infrastructure/config"
)

// cmdEnv is what almost every command needs before it can do anything: the
// configuration, the severity policy derived from it, and a logger. Loading it
// in one place keeps the flag-and-config plumbing out of each command, and
// keeps a mistake in it from having six slightly different versions.
type cmdEnv struct {
	cfg         *config.Config
	escalations map[finding.CWE]shared.Severity
	logger      ports.Logger
}

// loadEnv reads the persistent flags and the configuration file.
func loadEnv(cmd *cobra.Command) (cmdEnv, error) {
	cfgPath, _ := cmd.Root().PersistentFlags().GetString("config")
	logLevel, _ := cmd.Root().PersistentFlags().GetString("log-level")
	quiet, _ := cmd.Root().PersistentFlags().GetBool("quiet")

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return cmdEnv{}, configErr(fmt.Sprintf("load config: %v", err))
	}

	escalations, err := cfg.SeverityEscalations()
	if err != nil {
		return cmdEnv{}, configErr(err.Error())
	}

	return cmdEnv{
		cfg:         cfg,
		escalations: escalations,
		logger:      buildLogger(logLevel, quiet),
	}, nil
}

// policy builds the Quality Gate policy for commands that evaluate it.
func (e cmdEnv) policy() (gate.Policy, error) {
	policy, err := e.cfg.BuildPolicy()
	if err != nil {
		return policy, configErr(fmt.Sprintf("build gate policy: %v", err))
	}
	return policy, nil
}

// scanRequest assembles the ExecuteScan input from configuration, so scan,
// pipeline and baseline cannot drift apart in what they enable.
func (e cmdEnv) scanRequest(targetPath string) dto.ExecuteScanRequest {
	return dto.ExecuteScanRequest{
		TargetPath:   targetPath,
		Settings:     e.cfg.ScannerSettings(),
		Exclude:      e.cfg.ExcludePatterns(),
		Escalations:  e.escalations,
		Reachability: e.cfg.ReachabilitySettings(),
	}
}

// firstArgOr returns the first positional argument, or a default.
func firstArgOr(args []string, fallback string) string {
	if len(args) > 0 && args[0] != "" {
		return args[0]
	}
	return fallback
}
