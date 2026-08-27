// Package bootstrap composes the application from a loaded configuration.
//
// It exists because there is more than one way into Cortex: the CLI and the
// HTTP server both need the same object graph, and neither should own it.
// Everything here is hand-rolled dependency injection — no framework, no
// reflection, no init() side effects: reading it top to bottom tells you
// exactly which adapter satisfies which port.
package bootstrap

import (
	cryptorand "crypto/rand"
	"encoding/hex"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/application/services"
	"github.com/vektcore/cortex/internal/application/usecases"
	"github.com/vektcore/cortex/internal/domain/scan"
	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/infrastructure/config"
	gitinfra "github.com/vektcore/cortex/internal/infrastructure/git"
	langdetect "github.com/vektcore/cortex/internal/infrastructure/language_detection"
	"github.com/vektcore/cortex/internal/infrastructure/logging"
	"github.com/vektcore/cortex/internal/infrastructure/publishers/filesystem"
	"github.com/vektcore/cortex/internal/infrastructure/publishers/korvlabs"
	"github.com/vektcore/cortex/internal/infrastructure/reachability"
	infrasarif "github.com/vektcore/cortex/internal/infrastructure/sarif"
	"github.com/vektcore/cortex/internal/infrastructure/scanners"
	"github.com/vektcore/cortex/internal/infrastructure/scanners/bandit"
	eslint "github.com/vektcore/cortex/internal/infrastructure/scanners/eslint_security"
	"github.com/vektcore/cortex/internal/infrastructure/scanners/gitleaks"
	"github.com/vektcore/cortex/internal/infrastructure/scanners/gosec"
	"github.com/vektcore/cortex/internal/infrastructure/scanners/osv"
	scs "github.com/vektcore/cortex/internal/infrastructure/scanners/security_code_scan"
	"github.com/vektcore/cortex/internal/infrastructure/scanners/semgrep"
	"github.com/vektcore/cortex/internal/infrastructure/scanners/spotbugs"
	"github.com/vektcore/cortex/internal/infrastructure/scanners/trivy"
	"github.com/vektcore/cortex/internal/infrastructure/state"
	"github.com/vektcore/cortex/internal/infrastructure/symbols"
)

// RandomIDGen generates scan identifiers.
type RandomIDGen struct{}

// NewScanID returns a random 16-character hex identifier.
func (RandomIDGen) NewScanID() scan.ID {
	b := make([]byte, 8)
	_, _ = cryptorand.Read(b)
	return scan.ID(hex.EncodeToString(b))
}

// Logger returns the configured logger, falling back to a no-op one rather
// than failing a run because logging could not start.
func Logger(level string, quiet bool) ports.Logger {
	if quiet {
		return logging.NewNop()
	}
	l, err := logging.New(level)
	if err != nil {
		return logging.NewNop()
	}
	return l
}

// Codec returns the SARIF codec every scanner and publisher shares.
func Codec() ports.SarifCodec { return infrasarif.New() }

// Detector returns the language detector adapter.
func Detector() ports.LanguageDetector { return langdetect.New() }

// Registry registers every scanner whose Enabled flag is true. Scanners whose
// binary is missing from PATH stay registered — ExecuteScan isolates their
// failure and reports it as a non-fatal error.
func Registry(cfg *config.Config, codec ports.SarifCodec) *scanners.Registry {
	reg := scanners.New()
	if cfg.Scanners.Semgrep.Enabled {
		reg.Register(semgrep.New(codec, ""))
	}
	if cfg.Scanners.Bandit.Enabled {
		reg.Register(bandit.New(codec, ""))
	}
	if cfg.Scanners.Gosec.Enabled {
		reg.Register(gosec.New(codec, ""))
	}
	if cfg.Scanners.Gitleaks.Enabled {
		reg.Register(gitleaks.New(codec, ""))
	}
	if cfg.Scanners.EslintSecurity.Enabled {
		reg.Register(eslint.New(codec, ""))
	}
	if cfg.Scanners.Spotbugs.Enabled {
		reg.Register(spotbugs.New(codec, ""))
	}
	if cfg.Scanners.SecurityCodeScan.Enabled {
		reg.Register(scs.New(codec, ""))
	}
	if cfg.Scanners.OSV.Enabled {
		reg.Register(osv.New(codec, ""))
	}
	if cfg.Scanners.Trivy.Enabled {
		reg.Register(trivy.New(codec, ""))
	}
	return reg
}

// ExecuteScan wires the scan use case with real adapters.
func ExecuteScan(
	cfg *config.Config, codec ports.SarifCodec, logger ports.Logger,
) *usecases.ExecuteScan {
	return usecases.NewExecuteScan(usecases.ExecuteScanDeps{
		Registry: Registry(cfg, codec),
		Detector: langdetect.New(),
		Git:      gitinfra.New(),
		IDGen:    RandomIDGen{},
		Clock:    shared.SystemClock{},
		Logger:   logger,
		Symbols:  symbols.New(),
		Reach:    reachability.New(),
	})
}

// Store returns the vulnerability store, or nil when tracking is off.
//
// Which backend is chosen is the whole difference between a local tool and the
// client of a platform: a file the repository carries, or a project's history
// kept server-side. The application layer never learns which one it got.
func Store(cfg *config.Config) ports.VulnerabilityStore {
	if !cfg.State.Enabled {
		return nil
	}
	if cfg.State.Backend == config.StateBackendRemote {
		return state.NewRemote(
			cfg.State.Remote.URL,
			cfg.State.Remote.Token,
			cfg.State.Remote.Project,
		)
	}
	return state.New(cfg.State.Path)
}

// StoreAt returns a file-backed store at an explicit path, bypassing config.
// The server needs one store per project, which config cannot express.
func StoreAt(path string) ports.VulnerabilityStore { return state.New(path) }

// Reconcile wires the reconciliation use case. Returns nil when tracking is
// disabled, so callers can skip the whole step.
func Reconcile(cfg *config.Config, logger ports.Logger) *usecases.ReconcileVulnerabilities {
	store := Store(cfg)
	if store == nil {
		return nil
	}
	return ReconcileWith(store, logger)
}

// ReconcileWith wires reconciliation against a store the caller chose.
func ReconcileWith(
	store ports.VulnerabilityStore, logger ports.Logger,
) *usecases.ReconcileVulnerabilities {
	return usecases.NewReconcileVulnerabilities(usecases.ReconcileDeps{
		Store:  store,
		Clock:  shared.SystemClock{},
		Logger: logger,
	})
}

// Pipeline assembles the full scan → aggregate → gate → publish service.
func Pipeline(cfg *config.Config, logger ports.Logger) *services.Pipeline {
	codec := Codec()

	return services.NewPipeline(services.PipelineDeps{
		ExecuteScan:       ExecuteScan(cfg, codec, logger),
		AggregateFindings: usecases.NewAggregateFindings(),
		ApplyQualityGate:  usecases.NewApplyQualityGate(),
		PublishResults:    PublishResults(cfg, logger),
		Codec:             codec,
		Logger:            logger,
	})
}

// PublishResults wires the publish use case with the configured targets.
func PublishResults(cfg *config.Config, logger ports.Logger) *usecases.PublishResults {
	return usecases.NewPublishResults(usecases.PublishResultsDeps{
		Publishers: Publishers(cfg),
		Logger:     logger,
	})
}

// Publishers builds the enabled publisher set, keyed by name.
func Publishers(cfg *config.Config) map[string]ports.Publisher {
	m := make(map[string]ports.Publisher)
	if cfg.Publishers.Filesystem.Enabled {
		m["filesystem"] = filesystem.New(cfg.Publishers.Filesystem.OutputDir)
	}
	if cfg.Publishers.KorvLabs.Enabled {
		m["korvlabs"] = korvlabs.New(
			cfg.Publishers.KorvLabs.URL,
			cfg.Publishers.KorvLabs.APIKey,
		)
	}
	return m
}
