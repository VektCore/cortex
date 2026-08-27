// Package publishers ships scan results to external systems.
//
// Each publisher implements application/ports.Publisher. Cortex is
// publisher-agnostic: KorvLabs is one of several targets, not a hard
// dependency.
//
// Current adapters (Phase 0 stubs):
//
//	korvlabs/                 — POST SARIF to the KorvLabs platform
//	github_code_scanning/     — upload SARIF to the Security tab
//	gitlab_security/          — GitLab Security Dashboard
//	filesystem/               — write SARIF + JSON to disk
package publishers
