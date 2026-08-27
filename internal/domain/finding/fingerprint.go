package finding

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"unicode"
)

// FingerprintLength is the number of hex characters in a Fingerprint.
// 16 chars = 64 bits of entropy — sufficient for deduplication in any
// realistic scan size, and short enough to print in CLI output.
const FingerprintLength = 16

// Fingerprint is a deterministic, content-addressable identifier for a
// finding. Two findings with the same Fingerprint are duplicates by
// definition.
//
// The hash inputs are: RuleID, file path, start line, and a normalized
// snippet of the affected code. Whitespace and case are stripped from
// the snippet so that trivial reformatting does not change the
// fingerprint.
type Fingerprint string

// Three fingerprints identify the same finding at decreasing precision, so a
// triage decision (false positive, accepted risk) survives edits that a single
// hash cannot follow:
//
//	Exact    rule + file + lines + snippet     — the finding, where it was
//	Content  rule + file + snippet             — survives lines moving in the file
//	Symbol   rule + enclosing symbol + snippet — survives the function moving,
//	                                             even to another file
//
// Matching cascades from the most precise to the least (see Match), which is
// how issue tracking stays stable across refactors instead of resetting the
// team's triage on every commit.

// NewFingerprint computes the exact Fingerprint from its inputs. Pure function.
func NewFingerprint(rule RuleID, loc Location, snippet string) Fingerprint {
	h := sha256.New()
	writeField(h, string(rule))
	writeField(h, loc.File())
	writeUint32(h, uint32(loc.StartLine())) //nolint:gosec // line is non-negative
	writeUint32(h, uint32(loc.EndLine()))   //nolint:gosec
	writeField(h, normalizeSnippet(snippet))
	sum := h.Sum(nil)
	return Fingerprint(hex.EncodeToString(sum)[:FingerprintLength])
}

// NewContentFingerprint identifies the finding independently of its line
// numbers: inserting an import above it must not create a "new" finding.
func NewContentFingerprint(rule RuleID, loc Location, snippet string) Fingerprint {
	h := sha256.New()
	writeField(h, string(rule))
	writeField(h, loc.File())
	writeField(h, normalizeSnippet(snippet))
	return Fingerprint(hex.EncodeToString(h.Sum(nil))[:FingerprintLength])
}

// NewSymbolFingerprint identifies the finding by the symbol that contains it,
// with no file and no lines, so moving a function — even across files — keeps
// its findings identified.
//
// Returns "" when the symbol is unknown: an empty symbol would collapse every
// finding of a rule into one identity, which is worse than having no third
// level at all.
func NewSymbolFingerprint(rule RuleID, symbol, snippet string) Fingerprint {
	if strings.TrimSpace(symbol) == "" {
		return ""
	}
	h := sha256.New()
	writeField(h, string(rule))
	writeField(h, symbol)
	writeField(h, normalizeSnippet(snippet))
	return Fingerprint(hex.EncodeToString(h.Sum(nil))[:FingerprintLength])
}

func (f Fingerprint) String() string { return string(f) }

// Empty reports whether the fingerprint could not be computed.
func (f Fingerprint) Empty() bool { return f == "" }

func writeField(h interface{ Write([]byte) (int, error) }, s string) {
	_, _ = h.Write([]byte(s))
	_, _ = h.Write([]byte{0})
}

func writeUint32(h interface{ Write([]byte) (int, error) }, v uint32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	_, _ = h.Write(buf[:])
	_, _ = h.Write([]byte{0})
}

// normalizeSnippet removes whitespace and lower-cases letters so that
// formatting changes do not affect the fingerprint.
func normalizeSnippet(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}
