// Package semgrep adapts Semgrep (https://semgrep.dev) as a Cortex Scanner.
//
// Semgrep is invoked as a subprocess and its SARIF output is parsed via the
// shared SarifCodec. The adapter is pure w.r.t. global state: it only
// touches the filesystem when cmd.Run() is called and only via the subprocess.
package semgrep

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

const (
	// ScannerName is the canonical name registered in the registry.
	ScannerName = finding.ScannerName("semgrep")

	defaultConfig  = "auto"
	defaultTimeout = 5 * time.Minute
)

// Scanner adapts Semgrep as a Cortex SAST engine.
type Scanner struct {
	codec  ports.SarifCodec
	binary string
}

// New returns a Scanner that invokes the given binary (defaults to "semgrep").
func New(codec ports.SarifCodec, binary string) *Scanner {
	if binary == "" {
		binary = "semgrep"
	}
	return &Scanner{codec: codec, binary: binary}
}

func (s *Scanner) Name() finding.ScannerName { return ScannerName }

// SupportedLanguages returns the languages Semgrep handles natively.
// Semgrep supports many more, but these are the six that Cortex targets.
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

// Available reports whether the Semgrep binary is present on PATH.
func (s *Scanner) Available(_ context.Context) bool {
	_, err := exec.LookPath(s.binary)
	return err == nil
}

// Scan runs Semgrep against req.TargetPath and returns findings parsed from
// its SARIF output. A non-zero exit code from Semgrep is not an error when
// SARIF output is produced — Semgrep exits 1 whenever findings exist.
//
// Accepted options in req.Options:
//   - "config": Semgrep ruleset (default "auto"). Use "p/security-audit",
//     a path to a local .semgrep.yml, or a registry URL.
//   - "max_target_bytes": string int, passed as --max-target-bytes.
func (s *Scanner) Scan(ctx context.Context, req ports.ScanRequest) mo.Result[ports.ScanOutput] {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := s.buildArgs(req)

	cmd := exec.CommandContext(ctx, s.binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	raw := stdout.Bytes()

	// Semgrep exits 1 when it finds issues — that is NOT a tool failure.
	// Only treat it as an error when there is no SARIF output at all.
	if !isValidSARIF(raw) {
		msg := stderr.String()
		if runErr != nil {
			return shared.Err[ports.ScanOutput](fmt.Errorf("semgrep: %w; stderr: %s", runErr, msg))
		}
		return shared.Err[ports.ScanOutput](fmt.Errorf("semgrep: empty or invalid SARIF output; stderr: %s", msg))
	}

	findings, err := s.codec.Parse(raw).Get()
	if err != nil {
		return shared.Err[ports.ScanOutput](fmt.Errorf("semgrep: parse SARIF: %w", err))
	}

	return shared.Ok(ports.ScanOutput{
		Scanner:  ScannerName,
		Findings: findings,
		RawSARIF: raw,
	})
}

// excludeArgs turns Cortex path patterns into the gitignore-style patterns
// Semgrep expects: a trailing slash is dropped because Semgrep matches a bare
// directory name at any depth.
func excludeArgs(patterns []string) []string {
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if trimmed := strings.Trim(p, "/"); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// Environment fallbacks so a container image can point the adapter at the
// bundled rule pack without every repository configuring it.
const (
	envConfig   = "CORTEX_SEMGREP_CONFIG"
	envRulesDir = "CORTEX_SEMGREP_RULES"
)

func (s *Scanner) buildArgs(req ports.ScanRequest) []string {
	args := []string{
		"--sarif",
		"--quiet",
		"--no-rewrite-rule-ids",
		// Inside a git repository Semgrep silently narrows the scan to tracked
		// files and applies its own .semgrepignore, whose defaults drop test
		// directories. That makes the same code yield different findings
		// depending on whether it happens to be a git checkout — and it dropped
		// every file of Cortex's own fixture the moment this repo became one.
		// What gets scanned is decided by the engine's `exclude:` config, which
		// ExecuteScan enforces for every scanner alike.
		"--no-git-ignore",
	}

	// Multiple rule sources are the norm: the registry set plus Cortex's own
	// pack, which covers weaknesses the registry misses.
	for _, config := range splitConfigs(optionOrEnv(req.Options, "config", envConfig, defaultConfig)) {
		args = append(args, "--config", config)
	}
	if rules := optionOrEnv(req.Options, "rules_dir", envRulesDir, ""); rules != "" {
		args = append(args, "--config", rules)
	}

	for _, pattern := range excludeArgs(req.Exclude) {
		args = append(args, "--exclude", pattern)
	}

	if maxBytes, ok := req.Options["max_target_bytes"]; ok && maxBytes != "" {
		args = append(args, "--max-target-bytes", maxBytes)
	}

	args = append(args, req.TargetPath)
	return args
}

// splitConfigs accepts a comma-separated list so a single YAML string can name
// several rule sources: "auto,p/security-audit".
func splitConfigs(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// optionOrEnv resolves a value from the scan options first, then the
// environment, then the fallback.
func optionOrEnv(options map[string]string, key, env, fallback string) string {
	if v, ok := options[key]; ok && v != "" {
		return v
	}
	if v := os.Getenv(env); v != "" {
		return v
	}
	return fallback
}

// isValidSARIF does a minimal check: non-empty JSON object with a "version" field.
func isValidSARIF(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	var probe struct {
		Version string `json:"version"`
	}
	return json.Unmarshal(data, &probe) == nil && probe.Version != ""
}
