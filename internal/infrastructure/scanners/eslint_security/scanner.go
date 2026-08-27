// Package eslint_security adapts ESLint with the eslint-plugin-security plugin
// as a Cortex Scanner targeting JavaScript and TypeScript.
//
// ESLint is invoked as a subprocess and its SARIF output (via the
// @microsoft/eslint-formatter-sarif formatter) is parsed via the shared
// SarifCodec. ESLint exits 1 when linting errors are found; the adapter
// treats that as a success path when SARIF output is present.
package eslint_security

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
	ScannerName = finding.ScannerName("eslint-security")

	defaultFormatter = "@microsoft/eslint-formatter-sarif"
	defaultTimeout   = 5 * time.Minute
)

// Scanner adapts ESLint + eslint-plugin-security as a Cortex SAST engine.
type Scanner struct {
	codec  ports.SarifCodec
	binary string
}

// New returns a Scanner that invokes the given binary (defaults to "eslint").
func New(codec ports.SarifCodec, binary string) *Scanner {
	if binary == "" {
		binary = "eslint"
	}
	return &Scanner{codec: codec, binary: binary}
}

func (s *Scanner) Name() finding.ScannerName { return ScannerName }

// SupportedLanguages returns the languages this adapter handles.
func (s *Scanner) SupportedLanguages() []shared.Language {
	return []shared.Language{
		shared.LanguageJavaScript,
		shared.LanguageTypeScript,
	}
}

// Available reports whether the ESLint binary is present on PATH.
// The formatter availability is validated at runtime when Scan is called.
func (s *Scanner) Available(_ context.Context) bool {
	_, err := exec.LookPath(s.binary)
	return err == nil
}

// Scan runs ESLint against req.TargetPath and returns findings parsed from
// its SARIF output. ESLint exits 1 whenever linting errors exist — that is
// NOT a tool failure. Only treat it as an error when no SARIF output is
// produced.
//
// Accepted options in req.Options:
//   - "config": path to an ESLint config file. When unset, a temporary config
//     enabling plugin:security/recommended is generated — running with
//     --no-eslintrc alone activates no rule at all, so ESLint would always
//     report zero findings.
//   - "formatter": SARIF formatter name, or an absolute module path when the
//     formatter is installed globally instead of in the scanned project
//     (default "@microsoft/eslint-formatter-sarif").
//   - "plugins_dir": directory ESLint resolves plugins from, for a global
//     eslint-plugin-security install.
//
// "formatter" and "plugins_dir" fall back to CORTEX_ESLINT_FORMATTER and
// CORTEX_ESLINT_PLUGINS_DIR, so a container image can bake in its own paths
// without every repository having to configure them.
func (s *Scanner) Scan(ctx context.Context, req ports.ScanRequest) mo.Result[ports.ScanOutput] {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args, cleanup, argsErr := s.buildArgs(req)
	if argsErr != nil {
		return shared.Err[ports.ScanOutput](fmt.Errorf("eslint-security: %w", argsErr))
	}
	defer cleanup()

	cmd := exec.CommandContext(ctx, s.binary, args...)
	// The generated config lives in a temp directory, so Node cannot resolve a
	// globally installed plugin from there without NODE_PATH.
	if dir := optionOrEnv(req.Options, "plugins_dir", envPluginsDir, ""); dir != "" {
		cmd.Env = append(os.Environ(), "NODE_PATH="+dir)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	raw := stdout.Bytes()

	// ESLint exits 1 when it finds linting errors — that is not a tool failure.
	// Only treat it as an error when there is no SARIF output at all.
	if !isValidSARIF(raw) {
		msg := stderr.String()
		if runErr != nil {
			return shared.Err[ports.ScanOutput](fmt.Errorf("eslint-security: %w; stderr: %s", runErr, msg))
		}
		return shared.Err[ports.ScanOutput](fmt.Errorf("eslint-security: empty or invalid SARIF output; stderr: %s", msg))
	}

	findings, err := s.codec.Parse(raw).Get()
	if err != nil {
		return shared.Err[ports.ScanOutput](fmt.Errorf("eslint-security: parse SARIF: %w", err))
	}

	return shared.Ok(ports.ScanOutput{
		Scanner:  ScannerName,
		Findings: findings,
		RawSARIF: raw,
	})
}

// Environment fallbacks for the two path-dependent options, so a container
// image can point the adapter at its global Node installation once.
const (
	envFormatter  = "CORTEX_ESLINT_FORMATTER"
	envPluginsDir = "CORTEX_ESLINT_PLUGINS_DIR"
)

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

// buildArgs assembles the ESLint invocation. The returned cleanup removes the
// generated config, if any, and is always safe to call.
func (s *Scanner) buildArgs(req ports.ScanRequest) ([]string, func(), error) {
	noop := func() {}

	formatter := optionOrEnv(req.Options, "formatter", envFormatter, defaultFormatter)
	pluginsDir := optionOrEnv(req.Options, "plugins_dir", envPluginsDir, "")

	args := []string{
		"--format", formatter,
		"--plugin", "security",
		"--ext", ".js,.jsx,.ts,.tsx",
		"--no-eslintrc",
	}

	// ESLint resolves plugins relative to the current working directory, which
	// fails when eslint-plugin-security is installed globally instead of in the
	// scanned project. plugins_dir points the resolver at that install.
	if pluginsDir != "" {
		args = append(args, "--resolve-plugins-relative-to", pluginsDir)
	}

	for _, pattern := range ignorePatterns(req.Exclude) {
		args = append(args, "--ignore-pattern", pattern)
	}

	configPath, ok := req.Options["config"]
	cleanup := noop
	if !ok || configPath == "" {
		generated, tmpCleanup, err := writeDefaultConfig()
		if err != nil {
			return nil, noop, err
		}
		configPath, cleanup = generated, tmpCleanup
	}
	args = append(args, "--config", configPath, req.TargetPath)

	return args, cleanup, nil
}

// ignorePatterns renders the patterns in the glob form ESLint expects.
func ignorePatterns(patterns []string) []string {
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		trimmed := strings.Trim(p, "/")
		if trimmed == "" {
			continue
		}
		if strings.ContainsAny(trimmed, "*?") {
			out = append(out, "**/"+trimmed)
			continue
		}
		out = append(out, "**/"+trimmed+"/**")
	}
	return out
}

// defaultRules is the rule set of eslint-plugin-security, enabled explicitly.
//
// The plugin's own "plugin:security/recommended" preset is not usable here:
// v4 ships it in flat-config shape, which eslintrc mode rejects. Listing the
// rules keeps the adapter working across plugin versions. Override with the
// "config" option to use a project's own rule set instead.
var defaultRules = []string{
	"detect-unsafe-regex",
	"detect-non-literal-regexp",
	"detect-non-literal-require",
	"detect-non-literal-fs-filename",
	"detect-eval-with-expression",
	"detect-pseudoRandomBytes",
	"detect-possible-timing-attacks",
	"detect-no-csrf-before-method-override",
	"detect-buffer-noassert",
	"detect-child-process",
	"detect-disable-mustache-escape",
	"detect-object-injection",
	"detect-new-buffer",
	"detect-bidi-characters",
}

// defaultConfigJSON builds an eslintrc document enabling every security rule.
func defaultConfigJSON() ([]byte, error) {
	rules := make(map[string]string, len(defaultRules))
	for _, r := range defaultRules {
		rules["security/"+r] = "error"
	}
	// Without parserOptions ESLint 8 parses as ES5, so every modern file fails
	// with "The keyword 'const' is reserved" and no security rule ever runs.
	return json.Marshal(map[string]interface{}{
		"plugins": []string{"security"},
		"rules":   rules,
		"parserOptions": map[string]interface{}{
			"ecmaVersion": "latest",
			"sourceType":  "module",
			"ecmaFeatures": map[string]bool{
				"jsx": true,
			},
		},
		"env": map[string]bool{
			"node":    true,
			"browser": true,
			"es2024":  true,
		},
	})
}

func writeDefaultConfig() (string, func(), error) {
	f, err := os.CreateTemp("", "cortex-eslintrc-*.json")
	if err != nil {
		return "", func() {}, fmt.Errorf("create temp ESLint config: %w", err)
	}
	cleanup := func() { _ = os.Remove(f.Name()) }

	doc, err := defaultConfigJSON()
	if err != nil {
		_ = f.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("encode temp ESLint config: %w", err)
	}

	if _, err := f.Write(doc); err != nil {
		_ = f.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("write temp ESLint config: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("close temp ESLint config: %w", err)
	}
	return f.Name(), cleanup, nil
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
