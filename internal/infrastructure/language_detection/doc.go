// Package language_detection walks a target path and identifies which
// programming languages are present. The result drives which scanners
// are activated for a given scan.
//
// Strategy: extension + manifest detection (go.mod, pyproject.toml,
// package.json, pom.xml, *.csproj). Fast, deterministic, no parsing.
package language_detection
