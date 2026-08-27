package finding

import (
	"strings"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/domain/shared"
)

// Simple string-wrapping value objects.
//
// Each one carries semantic meaning that a bare string would not — a
// RuleID is not interchangeable with a Message even though both are
// strings. The compiler enforces the distinction.

// RuleID identifies the detection rule that produced a finding.
// Convention: "<scanner>.<rule>" (e.g. "semgrep.python.lang.security.xxe").
type RuleID string

func (r RuleID) String() string { return string(r) }
func (r RuleID) Empty() bool    { return r == "" }

// ScannerName identifies the tool that produced the finding.
type ScannerName string

func (s ScannerName) String() string { return string(s) }

// Message is the human-readable description of a finding.
type Message string

func (m Message) String() string { return string(m) }

// CWE wraps a Common Weakness Enumeration identifier (e.g. "CWE-89").
type CWE string

// NewCWE validates and returns a CWE. Accepts "89", "CWE-89", "cwe-89".
func NewCWE(raw string) mo.Result[CWE] {
	s := strings.ToUpper(strings.TrimSpace(raw))
	s = strings.TrimPrefix(s, "CWE-")
	if s == "" {
		return shared.Err[CWE](shared.NewDomainError("CWE_EMPTY", "empty CWE"))
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return shared.Err[CWE](shared.NewDomainError(
				"CWE_INVALID", "CWE must be numeric: "+raw))
		}
	}
	return shared.Ok(CWE("CWE-" + s))
}

func (c CWE) String() string { return string(c) }

// OWASP wraps an OWASP Top 10 category (e.g. "A03:2021").
type OWASP string

func (o OWASP) String() string { return string(o) }
