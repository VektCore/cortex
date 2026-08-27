// Package osv adapts osv-scanner (https://github.com/google/osv-scanner) as a
// Cortex Scanner.
//
// This is software composition analysis, not static analysis: it reads lock
// files and manifests and reports known vulnerabilities in the dependencies.
// Most of the exploitable CVEs in a real project live there rather than in code
// the team wrote, so a SAST-only pipeline reports on the smaller half of the
// risk.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// ScannerName is how this adapter identifies itself.
const ScannerName finding.ScannerName = "osv"

const (
	defaultBinary  = "osv-scanner"
	defaultTimeout = 5 * time.Minute
)

// Scanner runs osv-scanner and parses its SARIF output.
type Scanner struct {
	codec  ports.SarifCodec
	binary string
}

// New builds the adapter. An empty binary means "osv-scanner from PATH".
func New(codec ports.SarifCodec, binary string) *Scanner {
	if binary == "" {
		binary = defaultBinary
	}
	return &Scanner{codec: codec, binary: binary}
}

func (s *Scanner) Name() finding.ScannerName { return ScannerName }

// SupportedLanguages returns every language Cortex knows: dependency manifests
// exist for all of them, and osv-scanner decides what it recognises by looking
// at the files rather than being told a language.
func (s *Scanner) SupportedLanguages() []shared.Language {
	return []shared.Language{
		shared.LanguagePython,
		shared.LanguageJavaScript,
		shared.LanguageTypeScript,
		shared.LanguageJava,
		shared.LanguageGo,
		shared.LanguageCSharp,
	}
}

// Available reports whether the binary is present on PATH.
func (s *Scanner) Available(_ context.Context) bool {
	_, err := exec.LookPath(s.binary)
	return err == nil
}

// Scan runs osv-scanner against req.TargetPath.
//
// osv-scanner exits 1 when it finds vulnerabilities and 128 when the target
// carries no package source it understands. Neither is a failure: only a
// missing SARIF document with no explanation for it is.
//
// Accepted options in req.Options:
//   - "call_analysis": comma-separated languages to run reachability analysis
//     for ("go"). Rust is supported by the tool but runs dependency build
//     scripts, so enable it knowingly.
func (s *Scanner) Scan(ctx context.Context, req ports.ScanRequest) mo.Result[ports.ScanOutput] {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	raw, stderr, runErr := s.run(ctx, modernArgs(req))

	// osv-scanner 1.x took the target as a bare flag; 2.x moved it under
	// "scan source". Supporting both keeps the adapter working across the
	// versions a team may have installed.
	if !isValidSARIF(raw) && looksLikeUsageError(stderr) {
		raw, stderr, runErr = s.run(ctx, legacyArgs(req))
	}

	if !isValidSARIF(raw) {
		// A target with no manifest osv-scanner understands is an empty
		// result, not a failure. Reporting it as one marks the scanner broken
		// on every repository that has no dependency file it can read — a Java
		// project without a pom, say — and buries the real failures.
		if isNoPackagesFound(runErr, stderr) {
			return shared.Ok(ports.ScanOutput{Scanner: ScannerName})
		}
		if runErr != nil {
			return shared.Err[ports.ScanOutput](
				fmt.Errorf("osv: %w; stderr: %s", runErr, strings.TrimSpace(stderr)))
		}
		return shared.Err[ports.ScanOutput](fmt.Errorf(
			"osv: empty or invalid SARIF output; stderr: %s", strings.TrimSpace(stderr)))
	}

	findings, err := s.codec.Parse(raw).Get()
	if err != nil {
		return shared.Err[ports.ScanOutput](fmt.Errorf("osv: parse SARIF: %w", err))
	}

	return shared.Ok(ports.ScanOutput{
		Scanner:  ScannerName,
		Findings: findings,
		RawSARIF: raw,
	})
}

func (s *Scanner) run(ctx context.Context, args []string) ([]byte, string, error) {
	cmd := exec.CommandContext(ctx, s.binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.String(), err
}

// Path exclusion is deliberately not passed through: the flag has changed name
// across osv-scanner versions (--experimental-exclude today) and binding the
// adapter to one of them would break the others. ExecuteScan filters the
// findings by path afterwards, which is version-proof.

func modernArgs(req ports.ScanRequest) []string {
	args := []string{"scan", "source", "--format", "sarif", "--recursive"}
	args = append(args, callAnalysisArgs(req)...)
	return append(args, req.TargetPath)
}

func legacyArgs(req ports.ScanRequest) []string {
	args := []string{"--format", "sarif", "--recursive"}
	args = append(args, callAnalysisArgs(req)...)
	return append(args, req.TargetPath)
}

// callAnalysisArgs enables osv-scanner's own reachability analysis, which it
// supports for Go and Rust: a CVE in a dependency whose vulnerable function is
// never called is worth knowing about, but it is not the same emergency as one
// on a live code path.
//
// Off unless asked for, because for Rust it runs build scripts — arbitrary code
// from the dependency tree, which is not something to do implicitly.
func callAnalysisArgs(req ports.ScanRequest) []string {
	langs, ok := req.Options["call_analysis"]
	if !ok || langs == "" {
		return nil
	}
	out := make([]string, 0, 2)
	for _, lang := range strings.Split(langs, ",") {
		if trimmed := strings.TrimSpace(lang); trimmed != "" {
			out = append(out, "--call-analysis="+trimmed)
		}
	}
	return out
}

// noPackagesExitCode is what osv-scanner returns when it walked the target and
// found no package source to analyse.
const noPackagesExitCode = 128

// isNoPackagesFound distinguishes "nothing to scan here" from a real failure.
// Both the exit code and the message are checked because the code moved
// between osv-scanner 1.x and 2.x.
func isNoPackagesFound(runErr error, stderr string) bool {
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) && exitErr.ExitCode() == noPackagesExitCode {
		return true
	}
	return strings.Contains(strings.ToLower(stderr), "no package sources found")
}

func looksLikeUsageError(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "unknown command") ||
		strings.Contains(lower, "flag provided but not defined") ||
		strings.Contains(lower, "incorrect usage")
}

// isValidSARIF does a minimal check: non-empty JSON object with a "version".
func isValidSARIF(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	var probe struct {
		Version string `json:"version"`
	}
	return json.Unmarshal(data, &probe) == nil && probe.Version != ""
}
