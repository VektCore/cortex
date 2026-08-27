// Package scan models one execution of the Cortex engine.
//
// A Scan groups everything produced by running N scanners against a git
// revision: its findings, timing, status, and the rules each scanner used.
//
// Aggregate root: Scan
// Value Objects:  ScanID, Revision, Status (sum type), Duration
// Domain Events:  Started, Completed, Failed
//
// Status transitions are explicit and validated:
//
//	Queued → Running → Completed
//	                 ↘ Failed
package scan
