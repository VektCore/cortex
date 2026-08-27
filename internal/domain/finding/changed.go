package finding

// OnLines keeps only the findings that touch one of the given line ranges,
// keyed by file. It is the domain half of a "new code only" Quality Gate.
//
// A finding spanning several lines counts when any of them was touched: an
// edit inside a vulnerable block is a chance to fix it.
func OnLines(findings []Finding, changed map[string][]LineRange) []Finding {
	if len(findings) == 0 || len(changed) == 0 {
		return nil
	}

	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		ranges, touched := changed[f.location.File()]
		if !touched {
			continue
		}
		if overlaps(f, ranges) {
			out = append(out, f)
		}
	}
	return out
}

// LineRange is an inclusive range of 1-based line numbers.
type LineRange struct {
	Start int
	End   int
}

func overlaps(f Finding, ranges []LineRange) bool {
	for _, r := range ranges {
		if f.location.StartLine() <= r.End && f.location.EndLine() >= r.Start {
			return true
		}
	}
	return false
}
