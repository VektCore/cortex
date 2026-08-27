// Package ruleset holds the knowledge that scanners fail to provide: which
// weakness a rule actually describes, and how severe it is in Cortex's terms.
//
// Two scanners in the MVP set emit no CWE at all (ESLint-security, Gitleaks),
// and Bandit tags only part of its rules. Without this mapping, gate rules
// written against CWEs never fire — the finding simply carries no CWE to match.
//
// Everything here is a pure lookup over static tables. No I/O, no state.
package ruleset

import (
	"strings"

	"github.com/vektcore/cortex/internal/domain/finding"
)

// cweByRule maps a scanner rule ID to the weakness it describes. Keys are
// lowercase and stored without a scanner prefix; lookup strips prefixes before
// matching, so both "detect-child-process" and "security/detect-child-process"
// resolve.
//
// Only mappings that are unambiguous are listed. A rule whose weakness depends
// on context is better left without a CWE than mislabelled.
var cweByRule = map[string]string{
	// ---- eslint-plugin-security -------------------------------------------
	"detect-unsafe-regex":                   "CWE-1333", // ReDoS
	"detect-non-literal-regexp":             "CWE-1333",
	"detect-non-literal-require":            "CWE-829", // untrusted functional component
	"detect-non-literal-fs-filename":        "CWE-22",  // path traversal
	"detect-eval-with-expression":           "CWE-95",  // eval injection
	"detect-pseudorandombytes":              "CWE-338", // weak PRNG
	"detect-possible-timing-attacks":        "CWE-208", // observable timing discrepancy
	"detect-no-csrf-before-method-override": "CWE-352", // CSRF
	"detect-buffer-noassert":                "CWE-119", // buffer bounds
	"detect-new-buffer":                     "CWE-119",
	"detect-child-process":                  "CWE-78",   // OS command injection
	"detect-disable-mustache-escape":        "CWE-79",   // XSS
	"detect-object-injection":               "CWE-1321", // prototype pollution
	"detect-bidi-characters":                "CWE-1007", // visually deceptive text

	// ---- bandit ----------------------------------------------------------
	// Bandit tags roughly half of its rules with a CWE; these are the ones
	// seen unlabelled in practice.
	//
	// Deliberately absent: the B4xx "blacklist import" rules. Importing
	// subprocess or pickle is not command injection or insecure
	// deserialization — the dangerous *use* is caught by B602/B603 and
	// B301/B302. Mapping the import to the exploit's CWE made a bare import
	// match CWE gate rules and, once escalated, fail the build.
	"b101": "CWE-703", // assert used — check of exceptional conditions
	"b102": "CWE-95",  // exec used
	"b103": "CWE-732", // permissive file permissions
	"b104": "CWE-200", // binding to all interfaces
	"b105": "CWE-798", // hardcoded password string
	"b106": "CWE-798", // hardcoded password as argument
	"b107": "CWE-798", // hardcoded password default
	"b108": "CWE-377", // insecure temp file
	"b110": "CWE-703", // try/except/pass
	"b112": "CWE-703", // try/except/continue
	"b113": "CWE-400", // request without timeout
	"b301": "CWE-502", // pickle
	"b302": "CWE-502", // marshal
	"b303": "CWE-327", // insecure hash
	"b304": "CWE-327", // insecure cipher
	"b305": "CWE-327", // insecure cipher mode
	"b306": "CWE-377", // mktemp
	"b307": "CWE-95",  // eval
	"b308": "CWE-79",  // mark_safe
	"b310": "CWE-22",  // urllib urlopen
	"b311": "CWE-338", // random
	"b312": "CWE-319", // telnet
	"b313": "CWE-611", // XML — XXE
	"b314": "CWE-611",
	"b315": "CWE-611",
	"b316": "CWE-611",
	"b317": "CWE-611",
	"b318": "CWE-611",
	"b319": "CWE-611",
	"b320": "CWE-611",
	"b321": "CWE-319", // ftplib
	"b323": "CWE-295", // unverified context
	"b324": "CWE-328", // weak hash
	"b325": "CWE-377", // tempnam
	"b413": "CWE-327", // pycrypto
	"b501": "CWE-295", // request with verify=False
	"b502": "CWE-327", // ssl with bad version
	"b503": "CWE-327",
	"b504": "CWE-295",
	"b505": "CWE-326", // weak key size
	"b506": "CWE-20",  // yaml.load
	"b507": "CWE-295", // ssh no host key verification
	"b601": "CWE-78",  // paramiko calls
	"b602": "CWE-78",  // subprocess with shell=True
	"b603": "CWE-78",
	"b604": "CWE-78",
	"b605": "CWE-78",
	"b606": "CWE-78",
	"b607": "CWE-78",
	"b608": "CWE-89", // hardcoded SQL expression
	"b609": "CWE-78", // wildcard injection
	"b610": "CWE-89", // django extra
	"b611": "CWE-89", // django rawsql
	"b701": "CWE-79", // jinja2 autoescape false
	"b702": "CWE-79", // mako templates
	"b703": "CWE-79", // django mark_safe
}

// cweOverrides replaces the CWE a scanner reported when the tables know a more
// precise one. Kept deliberately tiny: overriding a tool is only justified when
// it reports a parent weakness and the child is unambiguous.
//
//	Bandit tags its weak-hash rules CWE-327 ("broken or risky algorithm"), the
//	parent of CWE-328 ("use of weak hash"), which is what a hash finding is.
var cweOverrides = map[string]string{
	"b303": "CWE-328", // insecure hash function
	"b324": "CWE-328", // hashlib with a weak algorithm
}

// gitleaksCWE applies to every Gitleaks rule: each one reports a credential
// committed to the repository.
const gitleaksCWE = "CWE-798"

// prefixesToStrip are the scanner namespaces that appear in rule IDs.
var prefixesToStrip = []string{"security/", "bandit.", "semgrep.", "gitleaks."}

// CWEFor returns the CWE a rule describes, if the tables know it.
func CWEFor(scanner finding.ScannerName, rule finding.RuleID) (finding.CWE, bool) {
	if strings.EqualFold(string(scanner), "gitleaks") {
		cwe, err := finding.NewCWE(gitleaksCWE).Get()
		return cwe, err == nil
	}

	key := strings.ToLower(strings.TrimSpace(rule.String()))
	for _, prefix := range prefixesToStrip {
		key = strings.TrimPrefix(key, prefix)
	}

	raw, ok := cweByRule[key]
	if !ok {
		return "", false
	}
	cwe, err := finding.NewCWE(raw).Get()
	return cwe, err == nil
}

// EnrichCWE fills in the CWE of every finding that lacks one and whose rule the
// tables recognise. Findings that already carry a CWE are never overwritten:
// what the scanner itself reported is more specific than a static table.
func EnrichCWE(findings []finding.Finding) []finding.Finding {
	if len(findings) == 0 {
		return findings
	}

	out := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		if override, ok := overrideFor(f.RuleID()); ok {
			out = append(out, f.WithCWE(override))
			continue
		}
		if _, has := f.CWE().Get(); has {
			out = append(out, f)
			continue
		}
		if cwe, ok := CWEFor(f.Source(), f.RuleID()); ok {
			out = append(out, f.WithCWE(cwe))
			continue
		}
		out = append(out, f)
	}
	return out
}

func overrideFor(rule finding.RuleID) (finding.CWE, bool) {
	raw, ok := cweOverrides[strings.ToLower(strings.TrimSpace(rule.String()))]
	if !ok {
		return "", false
	}
	cwe, err := finding.NewCWE(raw).Get()
	return cwe, err == nil
}
