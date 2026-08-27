package finding

// Deduplicate returns a new slice containing at most one Finding per
// Fingerprint. When duplicates exist, the highest-severity occurrence
// wins; if severities tie, the first occurrence in the input wins —
// preserving deterministic order.
//
// This is a pure function: it never mutates its input.
func Deduplicate(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}

	byFP := make(map[Fingerprint]Finding, len(findings))
	order := make([]Fingerprint, 0, len(findings))

	for _, f := range findings {
		existing, seen := byFP[f.fingerprint]
		if !seen {
			byFP[f.fingerprint] = f
			order = append(order, f.fingerprint)
			continue
		}
		if f.severity > existing.severity {
			byFP[f.fingerprint] = f
		}
	}

	out := make([]Finding, len(order))
	for i, fp := range order {
		out[i] = byFP[fp]
	}
	return out
}

// DeduplicateByScanner deduplicates only within the same Source. Used
// when callers want to preserve cross-scanner agreement as multiple
// hits (e.g. for confidence scoring) but still collapse intra-scanner
// duplicates.
func DeduplicateByScanner(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}
	type key struct {
		fp     Fingerprint
		source ScannerName
	}
	seen := make(map[key]struct{}, len(findings))
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		k := key{fp: f.fingerprint, source: f.source}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, f)
	}
	return out
}
