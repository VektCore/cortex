// Package ruleset describes which detection rules are enabled for each
// scanner and language.
//
// A Ruleset is the projection of "what we want to detect" — independent
// of the scanner that detects it. Adapters in infrastructure/scanners
// translate Rulesets into native scanner configuration (Semgrep configs,
// Bandit profiles, ESLint configs, …).
package ruleset
