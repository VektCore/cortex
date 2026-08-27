// Package logging provides the project-wide structured logger (zap).
//
// Use zap.Logger via dependency injection — do not access a package-level
// singleton from business code. The CLI layer constructs the logger and
// passes it into use cases.
package logging
