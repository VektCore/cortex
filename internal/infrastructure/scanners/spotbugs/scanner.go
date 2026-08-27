// Package spotbugs adapts SpotBugs (https://spotbugs.github.io) as a Cortex
// Scanner targeting Java bytecode.
//
// SpotBugs is invoked as a subprocess against a directory of compiled .class
// files or a .jar archive. SARIF output is written to stdout via the -sarif
// flag and parsed via the shared SarifCodec.
package spotbugs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

const (
	// ScannerName is the canonical name registered in the registry.
	ScannerName = finding.ScannerName("spotbugs")

	defaultTimeout = 10 * time.Minute
)

// Scanner adapts SpotBugs as a Cortex SAST engine.
type Scanner struct {
	codec  ports.SarifCodec
	binary string
}

// New returns a Scanner that invokes the given binary (defaults to "spotbugs").
func New(codec ports.SarifCodec, binary string) *Scanner {
	if binary == "" {
		binary = "spotbugs"
	}
	return &Scanner{codec: codec, binary: binary}
}

func (s *Scanner) Name() finding.ScannerName { return ScannerName }

// SupportedLanguages returns the languages this adapter handles.
func (s *Scanner) SupportedLanguages() []shared.Language {
	return []shared.Language{
		shared.LanguageJava,
	}
}

// Available reports whether the SpotBugs binary is present on PATH.
func (s *Scanner) Available(_ context.Context) bool {
	_, err := exec.LookPath(s.binary)
	return err == nil
}

// Scan runs SpotBugs against compiled Java classes and returns findings parsed
// from its SARIF output. The classes directory is determined by:
//  1. req.Options["classes_dir"] if set.
//  2. Common Maven/Gradle output directories inside req.TargetPath.
//  3. req.TargetPath itself as a fallback.
//
// Accepted options in req.Options:
//   - "classes_dir": explicit path to the directory of compiled .class files or
//     a .jar archive to analyse.
func (s *Scanner) Scan(ctx context.Context, req ports.ScanRequest) mo.Result[ports.ScanOutput] {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	classesDir := findClassesDir(req.TargetPath)
	if cd, ok := req.Options["classes_dir"]; ok && cd != "" {
		classesDir = cd
	}

	cmd := exec.CommandContext(ctx, s.binary, "-sarif", "-textui", classesDir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	raw := stdout.Bytes()

	if !isValidSARIF(raw) {
		msg := stderr.String()
		if runErr != nil {
			return shared.Err[ports.ScanOutput](fmt.Errorf("spotbugs: %w; stderr: %s", runErr, msg))
		}
		return shared.Err[ports.ScanOutput](fmt.Errorf("spotbugs: empty or invalid SARIF output; stderr: %s", msg))
	}

	findings, err := s.codec.Parse(raw).Get()
	if err != nil {
		return shared.Err[ports.ScanOutput](fmt.Errorf("spotbugs: parse SARIF: %w", err))
	}

	return shared.Ok(ports.ScanOutput{
		Scanner:  ScannerName,
		Findings: findings,
		RawSARIF: raw,
	})
}

// findClassesDir checks common compiled output directories inside targetPath
// and returns the first that exists. Falls back to targetPath itself.
func findClassesDir(targetPath string) string {
	candidates := []string{
		filepath.Join(targetPath, "target", "classes"),                  // Maven
		filepath.Join(targetPath, "build", "classes", "java", "main"),   // Gradle
		filepath.Join(targetPath, "build", "classes", "kotlin", "main"), // Gradle Kotlin
		filepath.Join(targetPath, "out", "production", "classes"),       // IntelliJ
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return targetPath
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
