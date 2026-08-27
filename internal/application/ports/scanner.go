package ports

import (
	"context"
	"time"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// ScanRequest describes one scanner invocation.
type ScanRequest struct {
	TargetPath string
	Languages  []shared.Language
	Timeout    time.Duration
	// Exclude lists path patterns the scanner should skip. Adapters translate
	// them to their tool's own flag where one exists; ExecuteScan filters the
	// remaining findings for the tools that have none.
	Exclude []string
	// Options carries scanner-specific configuration. Keys and shape are
	// opaque to the application layer; adapters interpret them.
	Options map[string]string
}

// ScanOutput is the result of one scanner invocation.
type ScanOutput struct {
	Scanner  finding.ScannerName
	Findings []finding.Finding
	// RawSARIF is the underlying SARIF document; preserved so publishers
	// that accept SARIF can forward it unchanged.
	RawSARIF []byte
}

// Scanner is implemented by every concrete SAST tool adapter
// (Semgrep, Bandit, ESLint, gosec, SpotBugs, SecurityCodeScan, Gitleaks…).
//
// Adapters are pure with respect to their inputs except for the
// inevitable subprocess invocation; they MUST NOT touch global state.
type Scanner interface {
	Name() finding.ScannerName
	SupportedLanguages() []shared.Language

	// Available reports whether the scanner can be invoked on the
	// current host (binary present, dependencies installed, license OK).
	Available(ctx context.Context) bool

	// Scan runs the scanner and returns its findings (plus the raw
	// SARIF). On failure the Result carries an error and no partial
	// findings.
	Scan(ctx context.Context, req ScanRequest) mo.Result[ScanOutput]
}

// ScannerRegistry indexes Scanners by name and language. Concrete
// implementations live in infrastructure/scanners.
type ScannerRegistry interface {
	Register(s Scanner)
	Get(name finding.ScannerName) mo.Option[Scanner]
	All() []Scanner
	ForLanguage(lang shared.Language) []Scanner
	ForLanguages(langs []shared.Language) []Scanner
}
