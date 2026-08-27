// Package services contains application services that orchestrate
// multiple use cases as a single higher-level operation.
//
// Example: PipelineService composes ExecuteScan → AggregateFindings →
// ApplyQualityGate → PublishResults into one transaction used by the
// `cortex pipeline` CLI command.
package services
