// Package security_code_scan adapts Security Code Scan
// (https://security-code-scan.github.io) as a Cortex Scanner targeting C#.
//
// The adapter drives the `dotnet build` command with the Security Code Scan
// MSBuild integration enabled. SARIF output is written to a temp file and
// parsed via the shared SarifCodec after the build completes.
package security_code_scan

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

const (
	// ScannerName is the canonical name registered in the registry.
	ScannerName = finding.ScannerName("security-code-scan")

	defaultTimeout = 10 * time.Minute
)

// Scanner adapts Security Code Scan as a Cortex SAST engine.
type Scanner struct {
	codec  ports.SarifCodec
	binary string
}

// New returns a Scanner that invokes the given binary (defaults to "dotnet").
func New(codec ports.SarifCodec, binary string) *Scanner {
	if binary == "" {
		binary = "dotnet"
	}
	return &Scanner{codec: codec, binary: binary}
}

func (s *Scanner) Name() finding.ScannerName { return ScannerName }

// SupportedLanguages returns the languages this adapter handles.
func (s *Scanner) SupportedLanguages() []shared.Language {
	return []shared.Language{
		shared.LanguageCSharp,
	}
}

// Available reports whether the dotnet binary is present on PATH.
func (s *Scanner) Available(_ context.Context) bool {
	_, err := exec.LookPath(s.binary)
	return err == nil
}

// Scan runs `dotnet build` with Security Code Scan enabled against the project
// or solution file found in req.TargetPath. SARIF output is written to a temp
// file and read back after the build.
//
// Returns an empty ScanOutput (no findings) when the build succeeds but
// produces no SARIF content.
func (s *Scanner) Scan(ctx context.Context, req ports.ScanRequest) mo.Result[ports.ScanOutput] {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	projectFile := findProjectFile(req.TargetPath)
	if projectFile == "" {
		return shared.Err[ports.ScanOutput](fmt.Errorf(
			"security-code-scan: no .sln or .csproj file found in %s", req.TargetPath,
		))
	}

	tmpFile, err := os.CreateTemp("", "cortex-scs-*.sarif")
	if err != nil {
		return shared.Err[ports.ScanOutput](fmt.Errorf("security-code-scan: create temp file: %w", err))
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	args := []string{
		"build", projectFile,
		"-p:EnableSecurityCodeScan=true",
		fmt.Sprintf("-p:SecurityCodeScanAdditionalOutputPath=%s", tmpPath),
		"--nologo",
		"-v", "quiet",
	}

	cmd := exec.CommandContext(ctx, s.binary, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if runErr := cmd.Run(); runErr != nil {
		return shared.Err[ports.ScanOutput](fmt.Errorf(
			"security-code-scan: dotnet build: %w; stderr: %s", runErr, stderr.String(),
		))
	}

	raw, err := os.ReadFile(tmpPath)
	if err != nil {
		return shared.Err[ports.ScanOutput](fmt.Errorf("security-code-scan: read SARIF output: %w", err))
	}

	if len(bytes.TrimSpace(raw)) == 0 {
		return shared.Ok(ports.ScanOutput{
			Scanner:  ScannerName,
			Findings: nil,
			RawSARIF: nil,
		})
	}

	findings, parseErr := s.codec.Parse(raw).Get()
	if parseErr != nil {
		return shared.Err[ports.ScanOutput](fmt.Errorf("security-code-scan: parse SARIF: %w", parseErr))
	}

	return shared.Ok(ports.ScanOutput{
		Scanner:  ScannerName,
		Findings: findings,
		RawSARIF: raw,
	})
}

// findProjectFile walks path looking for a project file. Preference order:
//  1. First *.sln found.
//  2. First *.csproj found.
//  3. Empty string when nothing is found.
func findProjectFile(path string) string {
	var sln, csproj string

	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		// An unreadable directory is not fatal here: the walk is a best-effort
		// search for a project file, and "not found" is a valid answer that the
		// caller already handles.
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // deliberate: keep walking
		}
		name := strings.ToLower(d.Name())
		switch {
		case strings.HasSuffix(name, ".sln") && sln == "":
			sln = p
		case strings.HasSuffix(name, ".csproj") && csproj == "":
			csproj = p
		}
		// Stop early once we have a .sln.
		if sln != "" {
			return filepath.SkipAll
		}
		return nil
	})

	if sln != "" {
		return sln
	}
	return csproj
}
