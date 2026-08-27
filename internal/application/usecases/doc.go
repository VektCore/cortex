// Package usecases holds the application's use cases.
//
// A use case is a thin coordinator: it receives a request DTO, calls the
// domain (pure logic) and ports (side effects), and returns a response
// DTO. Use cases never embed infrastructure-specific knowledge.
//
// Each use case lives in its own file:
//   - execute_scan.go         — drive scanners, collect Findings
//   - aggregate_findings.go   — merge + deduplicate
//   - apply_quality_gate.go   — evaluate GatePolicy → Verdict
//   - compare_baseline.go     — keep only "new" findings vs a baseline
//   - publish_results.go      — fan-out to all configured publishers
package usecases
