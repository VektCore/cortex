package finding

// DiffNew returns the subset of current that is NOT present in baseline,
// matched by Fingerprint. Used for differential gating: a PR is judged
// only on the findings it introduces, not on legacy ones.
//
// Pure function; preserves the input order of current.
func DiffNew(current, baseline []Finding) []Finding {
	if len(baseline) == 0 {
		return append([]Finding(nil), current...)
	}
	inBaseline := make(map[Fingerprint]struct{}, len(baseline))
	for _, b := range baseline {
		inBaseline[b.fingerprint] = struct{}{}
	}
	out := make([]Finding, 0, len(current))
	for _, c := range current {
		if _, ok := inBaseline[c.fingerprint]; !ok {
			out = append(out, c)
		}
	}
	return out
}

// DiffFixed returns the subset of baseline that is NOT present in
// current — findings that were "fixed" between the two snapshots.
func DiffFixed(current, baseline []Finding) []Finding {
	return DiffNew(baseline, current)
}
