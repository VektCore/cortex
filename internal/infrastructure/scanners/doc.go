// Package scanners hosts concrete Scanner adapters.
//
// Each subpackage wraps one external tool, invokes it as a subprocess,
// parses its SARIF (or native) output, and maps the result to domain
// Finding value objects.
//
// Current adapters (Phase 0 stubs):
//
//	semgrep/             — multi-language SAST (default everywhere)
//	bandit/              — Python-specific
//	eslint_security/     — JavaScript / TypeScript
//	spotbugs/            — Java (with find-sec-bugs plugin)
//	gosec/               — Go
//	security_code_scan/  — C# / .NET (Roslyn analyzer)
//	gitleaks/            — secret detection (cross-language)
//
// To add a new scanner:
//  1. Create a new subpackage here.
//  2. Implement application/ports.Scanner.
//  3. Register it in registry.go.
//  4. Add an ADR if it changes the architecture.
package scanners
