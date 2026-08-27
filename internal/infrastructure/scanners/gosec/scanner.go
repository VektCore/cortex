// Package gosec adapts Gosec (https://github.com/securego/gosec) as a Cortex Scanner.
//
// Gosec is invoked as a subprocess and its SARIF output is parsed via the
// shared SarifCodec. The adapter is pure w.r.t. global state: it only
// touches the filesystem when cmd.Run() is called and only via the subprocess.
package gosec

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

const (
	// ScannerName is the canonical name registered in the registry.
	ScannerName = finding.ScannerName("gosec")

	defaultTimeout = 5 * time.Minute
)

// Scanner adapts Gosec as a Cortex SAST engine.
type Scanner struct {
	codec  ports.SarifCodec
	binary string
}

// New returns a Scanner that invokes the given binary (defaults to "gosec").
func New(codec ports.SarifCodec, binary string) *Scanner {
	if binary == "" {
		binary = "gosec"
	}
	return &Scanner{codec: codec, binary: binary}
}

func (s *Scanner) Name() finding.ScannerName { return ScannerName }

// SupportedLanguages returns the languages Gosec handles.
func (s *Scanner) SupportedLanguages() []shared.Language {
	return []shared.Language{
		shared.LanguageGo,
	}
}

// Available reports whether the Gosec binary is present on PATH.
func (s *Scanner) Available(_ context.Context) bool {
	_, err := exec.LookPath(s.binary)
	return err == nil
}

// Scan runs Gosec against req.TargetPath and returns findings parsed from
// its SARIF output. A non-zero exit code from Gosec is not an error when
// SARIF output is produced — Gosec exits 1 whenever findings exist.
//
// Gosec requires the Go package path pattern (e.g. ./...) so /... is appended
// to targetPath unless it already ends with /....
func (s *Scanner) Scan(ctx context.Context, req ports.ScanRequest) mo.Result[ports.ScanOutput] {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	target := req.TargetPath
	if !strings.HasSuffix(target, "/...") {
		target = target + "/..."
	}

	dirs := excludeDirs(req.Exclude)
	args := make([]string, 0, len(dirs)+3)
	args = append(args, "-fmt=sarif", "-quiet")
	for _, dir := range dirs {
		args = append(args, "-exclude-dir="+dir)
	}
	args = append(args, target)

	cmd := exec.CommandContext(ctx, s.binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	raw := stdout.Bytes()

	// Gosec exits 1 when it finds issues — that is NOT a tool failure.
	// Only treat it as an error when there is no SARIF output at all.
	if !isValidSARIF(raw) {
		msg := stderr.String()
		if runErr != nil {
			return shared.Err[ports.ScanOutput](fmt.Errorf("gosec: %w; stderr: %s", runErr, msg))
		}
		return shared.Err[ports.ScanOutput](fmt.Errorf("gosec: empty or invalid SARIF output; stderr: %s", msg))
	}

	findings, err := s.codec.Parse(raw).Get()
	if err != nil {
		return shared.Err[ports.ScanOutput](fmt.Errorf("gosec: parse SARIF: %w", err))
	}

	return shared.Ok(ports.ScanOutput{
		Scanner:  ScannerName,
		Findings: findings,
		RawSARIF: raw,
	})
}

// excludeDirs keeps only the directory-shaped patterns: gosec's -exclude-dir
// takes folder names, not globs over file names.
func excludeDirs(patterns []string) []string {
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
