package config

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/gate"
	"github.com/vektcore/cortex/internal/domain/ruleset"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// Config is the parsed representation of .cortex.yaml.
type Config struct {
	Version    string           `mapstructure:"version"`
	Exclude    []string         `mapstructure:"exclude"`
	Severity   SeverityConfig   `mapstructure:"severity"`
	State      StateConfig      `mapstructure:"state"`
	Reach      ReachConfig      `mapstructure:"reachability"`
	Dedup      DedupConfig      `mapstructure:"dedup"`
	Scanners   ScannersConfig   `mapstructure:"scanners"`
	Gate       GateConfig       `mapstructure:"gate"`
	Publishers PublishersConfig `mapstructure:"publishers"`
	Ignore     []IgnoreRule     `mapstructure:"ignore"`
	Server     ServerConfig     `mapstructure:"server"`
}

// ServerConfig configures `cortex serve`: the long-running mode where the
// engine is deployed once and clients point their CI at it with an API key,
// instead of every client installing the scanners themselves.
type ServerConfig struct {
	// Addr is the listen address, e.g. ":8080".
	Addr string `mapstructure:"addr"`
	// DataDir is where analyses, their SARIF and each project's vulnerability
	// state are persisted. It must survive restarts, or the history that makes
	// "3 new since last week" possible is lost.
	DataDir string `mapstructure:"data_dir"`
	// Workers caps concurrent analyses. Each one clones a repository and runs
	// several scanners, so this is the knob that keeps the box alive.
	Workers int `mapstructure:"workers"`
	// APIKeys are the credentials clients authenticate with. Names exist for
	// the logs: a request is attributed to a client, never to a raw key.
	APIKeys []APIKey `mapstructure:"api_keys"`
	// WebhookSecret is the shared secret GitHub signs its deliveries with.
	// Empty closes the webhook endpoint: an unauthenticated one lets anyone
	// make this server clone repositories on demand.
	WebhookSecret string `mapstructure:"webhook_secret"`
	// WebhookBranches limits which branches a push triggers an analysis for.
	// Empty means the repository's own default branch (plus main/master).
	WebhookBranches []string `mapstructure:"webhook_branches"`
}

// APIKey is one client credential.
type APIKey struct {
	Name string `mapstructure:"name"`
	Key  string `mapstructure:"key"`
}

// ScannersConfig holds per-scanner settings.
type ScannersConfig struct {
	Semgrep          ScannerConfig `mapstructure:"semgrep"`
	Bandit           ScannerConfig `mapstructure:"bandit"`
	Gosec            ScannerConfig `mapstructure:"gosec"`
	Gitleaks         ScannerConfig `mapstructure:"gitleaks"`
	OSV              ScannerConfig `mapstructure:"osv"`
	Trivy            ScannerConfig `mapstructure:"trivy"`
	EslintSecurity   ScannerConfig `mapstructure:"eslint_security"`
	Spotbugs         ScannerConfig `mapstructure:"spotbugs"`
	SecurityCodeScan ScannerConfig `mapstructure:"security_code_scan"`
}

// ScannerConfig holds settings for one scanner.
type ScannerConfig struct {
	Enabled bool              `mapstructure:"enabled"`
	Timeout string            `mapstructure:"timeout"` // e.g. "5m"
	Options map[string]string `mapstructure:"options"`
}

// Timeout parses the Timeout string, defaulting to def on parse error.
func (s ScannerConfig) TimeoutDuration(def time.Duration) time.Duration {
	if s.Timeout == "" {
		return def
	}
	d, err := time.ParseDuration(s.Timeout)
	if err != nil {
		return def
	}
	return d
}

// GateConfig holds the list of quality gate rules.
type GateConfig struct {
	Rules []RuleConfig `mapstructure:"rules"`
}

// RuleConfig describes one gate rule in YAML.
type RuleConfig struct {
	Name       string   `mapstructure:"name"`
	Severity   string   `mapstructure:"severity,omitempty"`
	CWEs       []string `mapstructure:"cwes,omitempty"`
	PathPrefix []string `mapstructure:"path_prefix,omitempty"`
	Threshold  string   `mapstructure:"threshold"` // ">= 1", "> 5", "= 0"
}

// PublishersConfig holds per-publisher settings.
type PublishersConfig struct {
	Filesystem FilesystemConfig `mapstructure:"filesystem"`
	KorvLabs   KorvLabsConfig   `mapstructure:"korvlabs"`
}

// FilesystemConfig configures the filesystem publisher.
type FilesystemConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	OutputDir string `mapstructure:"output_dir"`
}

// KorvLabsConfig configures the KorvLabs publisher.
type KorvLabsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	URL     string `mapstructure:"url"`
	APIKey  string `mapstructure:"api_key"`
}

// IgnoreRule suppresses a specific finding from gate evaluation.
type IgnoreRule struct {
	RuleID     string `mapstructure:"rule_id"`
	PathPrefix string `mapstructure:"path_prefix"`
	Expires    string `mapstructure:"expires"` // YYYY-MM-DD
	Reason     string `mapstructure:"reason"`
}

// envReference matches ${VAR} — braces required, so a lone "$" in a rule
// pattern or a password is left alone.
var envReference = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnvReferences replaces ${VAR} with the environment's value.
//
// Secrets belong in the environment, not in a committed YAML file, and every
// example config in this repository is written that way (api_key:
// ${KORVLABS_API_KEY}). Without this, those placeholders were loaded as
// literals — which meant a server deployed straight from the documented example
// accepted the string "${CLIENT_ACME_KEY}" as a valid API key.
//
// An undefined variable expands to empty rather than staying literal: an empty
// credential is rejected downstream, a literal one silently authenticates.
func expandEnvReferences(raw []byte) []byte {
	return envReference.ReplaceAllFunc(raw, func(match []byte) []byte {
		name := envReference.FindSubmatch(match)[1]
		return []byte(os.Getenv(string(name)))
	})
}

// Load reads .cortex.yaml at path. Missing file is not an error — defaults
// are applied.
//
// Two ways to keep secrets out of the file: ${VAR} anywhere in a value, and
// environment variables prefixed with CORTEX_ that override a key by path
// (dots as underscores, e.g. CORTEX_PUBLISHERS_KORVLABS_URL).
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetEnvPrefix("CORTEX")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	applyDefaults(v)

	raw, readErr := os.ReadFile(path)
	switch {
	case readErr == nil:
		if err := v.ReadConfig(bytes.NewReader(expandEnvReferences(raw))); err != nil {
			return nil, fmt.Errorf("read config %q: %w", path, err)
		}
	case os.IsNotExist(readErr):
		// No file: defaults only, which is a supported way to run.
	default:
		return nil, fmt.Errorf("read config %q: %w", path, readErr)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

func applyDefaults(v *viper.Viper) {
	v.SetDefault("version", "1")
	v.SetDefault("scanners.semgrep.enabled", true)
	v.SetDefault("scanners.bandit.enabled", true)
	v.SetDefault("scanners.gosec.enabled", true)
	v.SetDefault("scanners.gitleaks.enabled", true)
	// Dependency scanning: osv-scanner is a small static binary, so it is on by
	// default. Trivy needs a vulnerability database download, so it is opt-in.
	v.SetDefault("scanners.osv.enabled", true)
	v.SetDefault("scanners.trivy.enabled", false)
	v.SetDefault("scanners.eslint_security.enabled", false)
	v.SetDefault("scanners.spotbugs.enabled", false)
	v.SetDefault("scanners.security_code_scan.enabled", false)
	v.SetDefault("publishers.filesystem.enabled", true)
	v.SetDefault("publishers.filesystem.output_dir", "results/")
	v.SetDefault("publishers.korvlabs.enabled", false)
	v.SetDefault("dedup.cross_scanner", false)
	v.SetDefault("state.enabled", true)
	v.SetDefault("state.path", ".cortex/state.json")
	v.SetDefault("state.backend", StateBackendFile)
	v.SetDefault("server.addr", ":8080")
	v.SetDefault("server.data_dir", "/var/lib/cortex")
	v.SetDefault("server.workers", 2)
	v.SetDefault("reachability.enabled", true)
	v.SetDefault("reachability.demote", true)
	// Vendored and generated code is other people's problem: scanning it
	// produces findings nobody in this repository can act on.
	v.SetDefault("exclude", []string{
		"node_modules/", "vendor/", ".venv/", "venv/", "site-packages/",
		"dist/", "build/", "target/", "__pycache__/", ".git/",
		"*.min.js", "*.min.css",
	})
}

// ScannerSettings translates the per-scanner YAML block into the application
// DTO. An unparsable timeout is ignored in favour of the adapter's default.
func (c *Config) ScannerSettings() map[finding.ScannerName]dto.ScannerSettings {
	byName := map[string]ScannerConfig{
		"semgrep":            c.Scanners.Semgrep,
		"bandit":             c.Scanners.Bandit,
		"gosec":              c.Scanners.Gosec,
		"gitleaks":           c.Scanners.Gitleaks,
		"osv":                c.Scanners.OSV,
		"trivy":              c.Scanners.Trivy,
		"eslint-security":    c.Scanners.EslintSecurity,
		"spotbugs":           c.Scanners.Spotbugs,
		"security-code-scan": c.Scanners.SecurityCodeScan,
	}

	out := make(map[finding.ScannerName]dto.ScannerSettings, len(byName))
	for name, sc := range byName {
		settings := dto.ScannerSettings{Options: sc.Options}
		if sc.Timeout != "" {
			if d, err := time.ParseDuration(sc.Timeout); err == nil {
				settings.Timeout = d
			}
		}
		out[finding.ScannerName(name)] = settings
	}
	return out
}

// SeverityConfig configures how scanner severities become Cortex severities.
type SeverityConfig struct {
	// Escalate raises the severity of a weakness class: {CWE-89: critical}.
	// Empty means ruleset.DefaultEscalations(); an explicit empty map
	// (escalate: {}) disables escalation entirely.
	Escalate map[string]string `mapstructure:"escalate"`
	// NoDefaults skips the built-in escalations instead of merging with them.
	NoDefaults bool `mapstructure:"no_defaults"`
}

// StateConfig controls the vulnerability lifecycle store — the memory that
// turns a sequence of scans into vulnerability management.
type StateConfig struct {
	// Enabled turns tracking on. With it off, Cortex behaves like a stateless
	// scanner: every scan is the first one.
	Enabled bool `mapstructure:"enabled"`
	// Path to the state document. Committing it makes triage decisions travel
	// with the code and get reviewed like code.
	Path string `mapstructure:"path"`
	// Backend selects where the state lives: "file" (default) or "remote".
	// A repository belonging to someone else cannot carry our state document,
	// so a managed service keeps it server-side instead.
	Backend string `mapstructure:"backend"`
	// Remote configures the server-side backend. Ignored unless
	// Backend is "remote".
	Remote RemoteStateConfig `mapstructure:"remote"`
}

// Backend names for StateConfig.Backend.
const (
	StateBackendFile   = "file"
	StateBackendRemote = "remote"
)

// RemoteStateConfig points the state at a platform API.
type RemoteStateConfig struct {
	// URL is the API base, without a trailing path.
	URL string `mapstructure:"url"`
	// Token authenticates this project against the API.
	Token string `mapstructure:"token"`
	// Project identifies which project's history to reconcile against. Two
	// repositories sharing one project id would each look new to the other.
	Project string `mapstructure:"project"`
}

// ReachConfig configures the dead-code analysis.
type ReachConfig struct {
	// Enabled labels each finding as reachable, unreachable or unknown.
	Enabled bool `mapstructure:"enabled"`
	// Demote lowers unreachable findings by one severity step. On by default:
	// a weakness nothing calls should not outrank one on a live path.
	Demote bool `mapstructure:"demote"`
}

// ReachabilitySettings converts the YAML block into the application DTO.
func (c *Config) ReachabilitySettings() dto.ReachabilitySettings {
	return dto.ReachabilitySettings{Enabled: c.Reach.Enabled, Demote: c.Reach.Demote}
}

// DedupConfig configures deduplication beyond the per-rule default.
type DedupConfig struct {
	// CrossScanner collapses the same CWE reported at the same place by
	// different tools. Off by default: agreement between scanners is a
	// confidence signal, and hiding it silently would be worse than counting
	// twice.
	CrossScanner bool `mapstructure:"cross_scanner"`
}

// ExcludePatterns returns the paths kept out of the scan.
func (c *Config) ExcludePatterns() []string {
	return append([]string(nil), c.Exclude...)
}

// CrossScannerDedup reports whether cross-scanner collapsing is enabled.
func (c *Config) CrossScannerDedup() bool { return c.Dedup.CrossScanner }

// SeverityEscalations resolves the severity policy: the built-in defaults
// merged with the configured entries, which win on conflict.
func (c *Config) SeverityEscalations() (map[finding.CWE]shared.Severity, error) {
	out := make(map[finding.CWE]shared.Severity)
	if !c.Severity.NoDefaults {
		for cwe, sev := range ruleset.DefaultEscalations() {
			out[cwe] = sev
		}
	}

	for rawCWE, rawSev := range c.Severity.Escalate {
		cwe, err := finding.NewCWE(rawCWE).Get()
		if err != nil {
			return nil, fmt.Errorf("severity.escalate: invalid CWE %q: %w", rawCWE, err)
		}
		sev := shared.ParseSeverity(rawSev)
		if !sev.IsValid() || (sev == shared.SeverityInfo && !strings.EqualFold(rawSev, "info")) {
			return nil, fmt.Errorf("severity.escalate[%s]: unknown severity %q", rawCWE, rawSev)
		}
		out[cwe] = sev
	}
	return out, nil
}

// BuildPolicy converts the YAML gate config into a domain gate.Policy.
// If no rules are configured, a default "fail on any critical" policy applies.
func (c *Config) BuildPolicy() (gate.Policy, error) {
	rules := make([]gate.Rule, 0, len(c.Gate.Rules))
	for _, rc := range c.Gate.Rules {
		rule, err := buildRule(rc)
		if err != nil {
			return gate.NewPolicy(nil), fmt.Errorf("gate rule %q: %w", rc.Name, err)
		}
		rules = append(rules, rule)
	}

	if len(rules) == 0 {
		rules = defaultRules()
	}
	return gate.NewPolicy(rules), nil
}

func defaultRules() []gate.Rule {
	return []gate.Rule{
		gate.NewRule(
			"default-no-critical",
			gate.NewCriteria(gate.CriteriaInput{
				MinSeverity: shared.Some(shared.SeverityCritical),
			}),
			gate.NewThreshold(gate.OpGreaterEqual, 1),
		),
	}
}

func buildRule(rc RuleConfig) (gate.Rule, error) {
	op, val, err := parseThreshold(rc.Threshold)
	if err != nil {
		return gate.Rule{}, err
	}

	cIn := gate.CriteriaInput{}
	if rc.Severity != "" {
		sev := shared.ParseSeverity(rc.Severity)
		cIn.MinSeverity = shared.Some(sev)
	}
	for _, raw := range rc.CWEs {
		cwe, cweErr := finding.NewCWE(raw).Get()
		if cweErr != nil {
			return gate.Rule{}, fmt.Errorf("invalid CWE %q: %w", raw, cweErr)
		}
		cIn.CWEs = append(cIn.CWEs, cwe)
	}
	cIn.PathPrefix = rc.PathPrefix

	return gate.NewRule(
		rc.Name,
		gate.NewCriteria(cIn),
		gate.NewThreshold(op, val),
	), nil
}

// parseThreshold converts strings like ">=1", ">5", "=0", "<=3", "1" into
// a (Operator, count) pair. A bare number N is equivalent to ">=N".
func parseThreshold(s string) (gate.Operator, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return gate.OpGreaterEqual, 1, nil // sensible default
	}

	var op gate.Operator
	var numStr string

	switch {
	case strings.HasPrefix(s, ">="):
		op, numStr = gate.OpGreaterEqual, strings.TrimSpace(s[2:])
	case strings.HasPrefix(s, ">"):
		op, numStr = gate.OpGreater, strings.TrimSpace(s[1:])
	case strings.HasPrefix(s, "<="):
		op, numStr = gate.OpLessEqual, strings.TrimSpace(s[2:])
	case strings.HasPrefix(s, "<"):
		op, numStr = gate.OpLess, strings.TrimSpace(s[1:])
	case strings.HasPrefix(s, "="):
		op, numStr = gate.OpEqual, strings.TrimSpace(s[1:])
	default:
		op, numStr = gate.OpGreaterEqual, s
	}

	var n int
	if _, err := fmt.Sscanf(numStr, "%d", &n); err != nil {
		return 0, 0, fmt.Errorf("invalid threshold value %q in %q", numStr, s)
	}
	return op, n, nil
}
