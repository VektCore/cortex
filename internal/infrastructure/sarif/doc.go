// Package sarif provides SARIF v2.1.0 parsing and writing.
//
// Cortex uses SARIF as the canonical interchange format: every scanner
// output is normalized into SARIF and every publisher consumes SARIF.
// This keeps the core of the engine independent of any specific tool
// vocabulary.
//
// Implementation note: parsing is delegated to
// github.com/owenrumney/go-sarif, with a thin layer here that maps
// SARIF Results into domain.Finding value objects.
package sarif
