// Package trivy adapts Trivy (https://trivy.dev) as a Cortex Scanner, used for
// dependency vulnerabilities.
//
// Trivy overlaps with osv-scanner on purpose: they draw on different advisory
// sources, and when both report the same CVE that agreement is a confidence
// signal (see dedup.cross_scanner). Only the vulnerability scanner is enabled —
// misconfiguration and licence scanning are separate products, not SAST.
package trivy

import (
	"bytes"
	"context"
	"encoding/json"
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
const ScannerName finding.ScannerName = "trivy"

const (
	defaultBinary  = "trivy"
	defaultTimeout = 10 * time.Minute
)

// Scanner runs trivy and parses its SARIF output.
type Scanner struct {
	codec  ports.SarifCodec
	binary string
}

// New builds the adapter. An empty binary means "trivy from PATH".
func New(codec ports.SarifCodec, binary string) *Scanner {
	if binary == "" {
		binary = defaultBinary
	}
	return &Scanner{codec: codec, binary: binary}
}

func (s *Scanner) Name() finding.ScannerName { return ScannerName }

// SupportedLanguages returns every language: Trivy detects ecosystems from the
// files it finds.
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

// Scan runs trivy in filesystem mode.
//
// Accepted options in req.Options:
//   - "severity": comma-separated Trivy severities to report
//     (default "MEDIUM,HIGH,CRITICAL"; Cortex's own gate does the filtering,
//     but dropping UNKNOWN/LOW keeps the noise down).
//   - "scanners": Trivy scanners to run (default "vuln").
func (s *Scanner) Scan(ctx context.Context, req ports.ScanRequest) mo.Result[ports.ScanOutput] {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.binary, s.buildArgs(req)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	raw := stdout.Bytes()

	if !isValidSARIF(raw) {
		msg := strings.TrimSpace(stderr.String())
		if runErr != nil {
			return shared.Err[ports.ScanOutput](fmt.Errorf("trivy: %w; stderr: %s", runErr, msg))
		}
		return shared.Err[ports.ScanOutput](fmt.Errorf(
			"trivy: empty or invalid SARIF output; stderr: %s", msg))
	}

	findings, err := s.codec.Parse(raw).Get()
	if err != nil {
		return shared.Err[ports.ScanOutput](fmt.Errorf("trivy: parse SARIF: %w", err))
	}

	return shared.Ok(ports.ScanOutput{
		Scanner:  ScannerName,
		Findings: findings,
		RawSARIF: raw,
	})
}

func (s *Scanner) buildArgs(req ports.ScanRequest) []string {
	scanners := "vuln"
	if v, ok := req.Options["scanners"]; ok && v != "" {
		scanners = v
	}
	severity := "MEDIUM,HIGH,CRITICAL"
	if v, ok := req.Options["severity"]; ok && v != "" {
		severity = v
	}

	args := []string{
		"fs",
		"--format", "sarif",
		"--scanners", scanners,
		"--severity", severity,
		"--quiet",
		"--exit-code", "0",
	}
	for _, pattern := range skipDirs(req.Exclude) {
		args = append(args, "--skip-dirs", pattern)
	}
	return append(args, req.TargetPath)
}

// skipDirs keeps the directory-shaped patterns: --skip-dirs takes paths, not
// globs over file names.
func skipDirs(patterns []string) []string {
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		trimmed := strings.Trim(p, "/")
		if trimmed == "" || strings.ContainsAny(trimmed, "*?") {
			continue
		}
		out = append(out, trimmed)
	}
	return out
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
