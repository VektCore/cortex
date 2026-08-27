// Package bandit adapts Bandit (https://bandit.readthedocs.io) as a Cortex Scanner.
//
// Bandit is invoked as a subprocess and its SARIF output is parsed via the
// shared SarifCodec. The adapter is pure w.r.t. global state: it only
// touches the filesystem when cmd.Run() is called and only via the subprocess.
package bandit

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
	ScannerName = finding.ScannerName("bandit")

	defaultTimeout = 5 * time.Minute
)

// Scanner adapts Bandit as a Cortex SAST engine.
type Scanner struct {
	codec  ports.SarifCodec
	binary string
}

// New returns a Scanner that invokes the given binary (defaults to "bandit").
func New(codec ports.SarifCodec, binary string) *Scanner {
	if binary == "" {
		binary = "bandit"
	}
	return &Scanner{codec: codec, binary: binary}
}

func (s *Scanner) Name() finding.ScannerName { return ScannerName }

// SupportedLanguages returns the languages Bandit handles.
func (s *Scanner) SupportedLanguages() []shared.Language {
	return []shared.Language{
		shared.LanguagePython,
	}
}

// Available reports whether the Bandit binary is present on PATH.
func (s *Scanner) Available(_ context.Context) bool {
	_, err := exec.LookPath(s.binary)
	return err == nil
}

// Scan runs Bandit against req.TargetPath and returns findings parsed from
// its SARIF output. A non-zero exit code from Bandit is not an error when
// SARIF output is produced — Bandit exits 1 whenever findings exist.
func (s *Scanner) Scan(ctx context.Context, req ports.ScanRequest) mo.Result[ports.ScanOutput] {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{"-r", "-f", "sarif", "-q"}
	if excluded := banditExcludes(req.Exclude); excluded != "" {
		args = append(args, "-x", excluded)
	}
	args = append(args, req.TargetPath)

	cmd := exec.CommandContext(ctx, s.binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	raw := stdout.Bytes()

	// Bandit exits 1 when it finds issues — that is NOT a tool failure.
	// Only treat it as an error when there is no SARIF output at all.
	if !isValidSARIF(raw) {
		msg := stderr.String()
		if strings.Contains(msg, "invalid choice: 'sarif'") {
			return shared.Err[ports.ScanOutput](fmt.Errorf(
				"bandit: SARIF output unsupported — install the formatter plugin: " +
					"pip install bandit-sarif-formatter (pipx: pipx inject bandit bandit-sarif-formatter)"))
		}
		if runErr != nil {
			return shared.Err[ports.ScanOutput](fmt.Errorf("bandit: %w; stderr: %s", runErr, msg))
		}
		return shared.Err[ports.ScanOutput](fmt.Errorf("bandit: empty or invalid SARIF output; stderr: %s", msg))
	}

	findings, err := s.codec.Parse(raw).Get()
	if err != nil {
		return shared.Err[ports.ScanOutput](fmt.Errorf("bandit: parse SARIF: %w", err))
	}

	return shared.Ok(ports.ScanOutput{
		Scanner:  ScannerName,
		Findings: findings,
		RawSARIF: raw,
	})
}

// banditExcludes renders the patterns as the comma-separated glob list bandit
// takes in -x. Directory patterns get wrapped in wildcards because bandit
// matches against the full path, not the directory name.
func banditExcludes(patterns []string) string {
	out := make([]string, 0, len(patterns)*2)
	for _, p := range patterns {
		trimmed := strings.Trim(p, "/")
		if trimmed == "" {
			continue
		}
		if strings.ContainsAny(trimmed, "*?") {
			out = append(out, trimmed)
			continue
		}
		out = append(out, trimmed, "*/"+trimmed+"/*")
	}
	return strings.Join(out, ",")
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
