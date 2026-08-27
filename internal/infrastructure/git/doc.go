// Package git wraps the git binary to provide the diff-based information
// the differential gate needs (changed files between HEAD and a base ref,
// blame, etc.).
//
// Implementation uses os/exec; no CGO, no libgit2.
package git
