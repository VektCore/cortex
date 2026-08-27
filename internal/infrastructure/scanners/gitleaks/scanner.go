// Package gitleaks adapts Gitleaks (https://github.com/gitleaks/gitleaks) as a Cortex Scanner.
//
// Gitleaks is invoked as a subprocess. Unlike other scanners it writes SARIF
// output to a temp file rather than stdout. The adapter is pure w.r.t. global
// state aside from the temp file it creates and removes per scan.
package gitleaks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
	"github.com/vektcore/cortex/internal/infrastructure/secrets"
)

const (
	// ScannerName is the canonical name registered in the registry.
	ScannerName = finding.ScannerName("gitleaks")

	defaultTimeout = 3 * time.Minute
)

// Scanner adapts Gitleaks as a Cortex secrets scanner.
type Scanner struct {
	codec  ports.SarifCodec
	binary string
}

// New returns a Scanner that invokes the given binary (defaults to "gitleaks").
func New(codec ports.SarifCodec, binary string) *Scanner {
	if binary == "" {
		binary = "gitleaks"
	}
	return &Scanner{codec: codec, binary: binary}
}

func (s *Scanner) Name() finding.ScannerName { return ScannerName }

// SupportedLanguages returns all languages Gitleaks supports.
// Gitleaks performs secrets detection and is language-agnostic.
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

// Available reports whether the Gitleaks binary is present on PATH.
func (s *Scanner) Available(_ context.Context) bool {
	_, err := exec.LookPath(s.binary)
	return err == nil
}

// Scan runs Gitleaks against req.TargetPath and returns findings parsed from
// its SARIF output. Gitleaks writes SARIF to a temp file rather than stdout.
// --exit-code 0 ensures Gitleaks always exits 0 regardless of findings found.
//
// Accepted options in req.Options:
//   - "scan_git_history": "true" scans the commit history ("gitleaks git")
//     instead of the working tree ("gitleaks dir"). Requires a repository.
//   - "verify": "true" checks whether each detected credential still works and
//     ranks it accordingly. This sends the credential to its own provider in a
//     read-only call, so it is opt-in — see internal/infrastructure/secrets.
func (s *Scanner) Scan(ctx context.Context, req ports.ScanRequest) mo.Result[ports.ScanOutput] {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tmpFile, err := os.CreateTemp("", "cortex-gitleaks-*.sarif")
	if err != nil {
		return shared.Err[ports.ScanOutput](fmt.Errorf("gitleaks: create temp file: %w", err))
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	tmpFile.Close()

	// "dir" scans the working tree, with or without a .git directory. It
	// replaced "detect --source" / "detect --no-git" in gitleaks 8.19, and
	// "detect" no longer exists in 8.28+.
	args := []string{
		"dir", req.TargetPath,
		"--no-banner",
		"--exit-code", "0",
		"--report-format", "sarif",
		"--report-path", tmpPath,
	}
	if req.Options["scan_git_history"] == "true" {
		args[0] = "git"
	}

	cmd := exec.CommandContext(ctx, s.binary, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if runErr := cmd.Run(); runErr != nil {
		return shared.Err[ports.ScanOutput](fmt.Errorf("gitleaks: %w; stderr: %s", runErr, stderr.String()))
	}

	raw, readErr := os.ReadFile(tmpPath)
	if readErr != nil || len(raw) == 0 {
		// No secrets found — gitleaks did not write a report.
		return shared.Ok(ports.ScanOutput{
			Scanner:  ScannerName,
			Findings: nil,
			RawSARIF: nil,
		})
	}

	if !isValidSARIF(raw) {
		return shared.Err[ports.ScanOutput](fmt.Errorf("gitleaks: empty or invalid SARIF output"))
	}

	findings, err := s.codec.Parse(raw).Get()
	if err != nil {
		return shared.Err[ports.ScanOutput](fmt.Errorf("gitleaks: parse SARIF: %w", err))
	}

	if req.Options["verify"] == "true" {
		findings = verifyFindings(ctx, findings, raw)
	}

	return shared.Ok(ports.ScanOutput{
		Scanner:  ScannerName,
		Findings: findings,
		RawSARIF: raw,
	})
}

// verifyFindings ranks each detected credential by whether it still works.
//
// A live token is an incident: it goes to critical whatever the pattern's
// nominal severity was. A revoked one drops to low — it stays reported, because
// it is still in the repository's history and still needs removing, but it does
// not compete for attention with a working credential.
func verifyFindings(
	ctx context.Context, findings []finding.Finding, raw []byte,
) []finding.Finding {
	values := secretValues(raw)
	if len(values) == 0 {
		return findings
	}

	verifier := secrets.New(0)
	out := make([]finding.Finding, 0, len(findings))

	for _, f := range findings {
		secret, known := values[locationKey(f.Location().File(), f.Location().StartLine())]
		if !known || !verifier.Supports(f.RuleID().String()) {
			out = append(out, f)
			continue
		}

		validity, providerName := verifier.Verify(ctx, f.RuleID().String(), secret)
		switch validity {
		case secrets.ValidityLive:
			out = append(out, f.
				WithSeverity(shared.SeverityCritical).
				WithMessage(finding.Message(
					"VERIFIED LIVE ("+providerName+"): "+f.Message().String()+
						" — this credential still works; revoke it before anything else")))
		case secrets.ValidityRevoked:
			out = append(out, f.
				WithSeverity(shared.SeverityLow).
				WithMessage(finding.Message(
					"revoked ("+providerName+"): "+f.Message().String()+
						" — no longer valid, but still needs removing from the history")))
		case secrets.ValidityUnknown:
			// Nobody could tell: leave the scanner's own judgement alone.
			out = append(out, f)
		default:
			out = append(out, f)
		}
	}
	return out
}

// secretValues pulls the matched text out of the raw SARIF, keyed by location.
// The value never leaves this package's callers: it is not logged and not put
// into a Finding.
func secretValues(raw []byte) map[string]string {
	var doc struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
							Snippet   struct {
								Text string `json:"text"`
							} `json:"snippet"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}

	out := make(map[string]string)
	for _, run := range doc.Runs {
		for _, result := range run.Results {
			for _, loc := range result.Locations {
				phys := loc.PhysicalLocation
				text := strings.TrimSpace(phys.Region.Snippet.Text)
				if text == "" {
					continue
				}
				uri := strings.TrimPrefix(phys.ArtifactLocation.URI, "file://")
				out[locationKey(uri, phys.Region.StartLine)] = text
			}
		}
	}
	return out
}

// locationKey matches a finding to its raw entry. The finding's path has been
// normalized by then, so only the file name and line are compared.
func locationKey(path string, line int) string {
	return filepath.Base(path) + ":" + strconv.Itoa(line)
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
