// Package dto holds the data-transfer objects exchanged at the
// application boundary. DTOs are flat, serializable structs — no domain
// invariants, no behaviour.
package dto

import (
	"time"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/gate"
	"github.com/vektcore/cortex/internal/domain/scan"
	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/domain/vulnerability"
)

// IgnoreFilter describes one allowlist entry that suppresses matching findings
// from gate evaluation. Findings still appear in reports and SARIF output.
type IgnoreFilter struct {
	RuleID     string    // empty = match any rule
	PathPrefix string    // empty = match any path
	ExpiresAt  time.Time // zero = never expires
}

// ScannerSettings is the per-scanner configuration resolved by the primary
// adapter (CLI) from .cortex.yaml. Adapters interpret Options themselves.
type ScannerSettings struct {
	Timeout time.Duration     // 0 = the adapter's own default
	Options map[string]string // nil = no scanner-specific option
}

// ExecuteScanRequest is the input to the ExecuteScan use case.
type ExecuteScanRequest struct {
	TargetPath  string
	Scanners    []finding.ScannerName // empty = run every available
	Languages   []shared.Language     // empty = auto-detect
	Parallelism int                   // 0 = NumCPU
	// Settings carries per-scanner timeouts and options, keyed by scanner
	// name. A scanner absent from the map runs with its own defaults.
	Settings map[finding.ScannerName]ScannerSettings
	// Exclude lists path patterns kept out of the scan.
	Exclude []string
	// Escalations raises the severity of the listed weakness classes.
	Escalations map[finding.CWE]shared.Severity
	// Reachability configures the dead-code analysis.
	Reachability ReachabilitySettings
}

// ReachabilitySettings configures the analysis that separates findings on live
// code paths from findings in code nothing calls.
type ReachabilitySettings struct {
	Enabled bool
	// Demote lowers the severity of unreachable findings by one step. Labelling
	// without demoting is useful on its own: the report says which findings sit
	// in dead code, and the gate keeps treating them equally.
	Demote bool
}

// ExecuteScanResponse is the output of ExecuteScan.
type ExecuteScanResponse struct {
	Scan     scan.Scan
	Findings []finding.Finding
	// PerScanner holds the raw SARIF documents keyed by scanner name,
	// preserved for downstream publishers that prefer raw inputs.
	PerScanner map[finding.ScannerName][]byte
	// Errors collects scanners that failed; the use case never aborts on
	// a single scanner failure.
	Errors map[finding.ScannerName]error
}

// AggregateFindingsRequest groups multiple finding sets for merge+dedupe.
type AggregateFindingsRequest struct {
	Inputs [][]finding.Finding
	// CrossScanner also collapses the same CWE reported at the same place by
	// different tools. Off by default.
	CrossScanner bool
}

// AggregateFindingsResponse is the deduplicated union.
type AggregateFindingsResponse struct {
	Findings []finding.Finding
	// Corroborated counts weaknesses that more than one scanner reported.
	// Only meaningful when CrossScanner was requested.
	Corroborated int
}

// ApplyQualityGateRequest applies a Policy against a set of findings,
// optionally filtered by a baseline.
type ApplyQualityGateRequest struct {
	Findings []finding.Finding
	Policy   gate.Policy
	Baseline mo.Option[[]finding.Finding]
}

// ApplyQualityGateResponse carries the verdict plus the actually
// considered set (useful for debugging baseline filters).
type ApplyQualityGateResponse struct {
	Verdict    gate.Verdict
	Considered []finding.Finding
}

// PublishResultsRequest fans out a SARIF document to one or more
// publishers.
type PublishResultsRequest struct {
	Scan     scan.Scan
	Findings []finding.Finding
	SARIF    []byte
	Targets  []string // publisher names; empty = all configured
	Metadata map[string]string
}

// PublishResultsResponse aggregates receipts and per-publisher errors.
type PublishResultsResponse struct {
	Receipts []ports.PublishReceipt
	Errors   map[string]error
}

// ReconcileRequest folds a scan's findings into the stored state.
type ReconcileRequest struct {
	Findings []finding.Finding
	// Persist writes the reconciled state back. False for pull-request scans,
	// which must not rewrite the trunk's history.
	Persist bool
}

// ReconcileResponse carries the classification and how much was already known.
type ReconcileResponse struct {
	Result vulnerability.Reconciliation
	Known  int
	// PersistError reports that the reconciled state could not be written —
	// a read-only checkout, no permission. The reconciliation itself is still
	// valid, so the caller decides how loudly to complain: failing a scan that
	// already produced its results would be the wrong trade.
	PersistError error
}

// TriageRequest records a human decision about one vulnerability.
type TriageRequest struct {
	// Key is a fingerprint or a unique prefix of one.
	Key     string
	Status  vulnerability.Status
	Reason  string
	Author  string
	Expires mo.Option[time.Time]
}

// TriageResponse returns the updated vulnerability.
type TriageResponse struct {
	Vulnerability vulnerability.Vulnerability
}

// PipelineRequest is what the CLI passes to PipelineService.
type PipelineRequest struct {
	TargetPath   string
	Policy       gate.Policy
	Baseline     mo.Option[[]finding.Finding]
	Scanners     []finding.ScannerName
	Languages    []shared.Language
	Publishers   []string
	DryRun       bool
	Ignores      []IgnoreFilter
	Settings     map[finding.ScannerName]ScannerSettings
	Exclude      []string
	Escalations  map[finding.CWE]shared.Severity
	CrossScanner bool
	Reachability ReachabilitySettings
}

// PipelineResponse is the full result of one end-to-end execution.
type PipelineResponse struct {
	Scan     scan.Scan
	Verdict  gate.Verdict
	Findings []finding.Finding
	Receipts []ports.PublishReceipt
	Errors   []error
}
