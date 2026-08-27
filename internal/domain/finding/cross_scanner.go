package finding

// CrossScannerResult is the outcome of collapsing the same weakness reported by
// different tools.
type CrossScannerResult struct {
	// Findings is the collapsed set, highest severity per group.
	Findings []Finding
	// Corroborated counts the groups that more than one scanner reported.
	// Agreement between tools is a confidence signal, so it is surfaced rather
	// than silently discarded.
	Corroborated int
}

// crossKey identifies "the same weakness at the same place", independently of
// which rule of which tool found it.
type crossKey struct {
	cwe       CWE
	file      string
	startLine int
}

// DeduplicateCrossScanner collapses findings that share CWE, file and start
// line even when their rule IDs differ — Semgrep and Bandit both reporting the
// same SQL injection would otherwise count twice and inflate the gate.
//
// Only findings carrying a CWE participate: without one there is no evidence
// that two different rules describe the same weakness, and guessing would drop
// real findings. Everything else passes through untouched.
//
// The highest severity in a group wins, and the first occurrence decides the
// output order, so the result is deterministic.
func DeduplicateCrossScanner(findings []Finding) CrossScannerResult {
	if len(findings) == 0 {
		return CrossScannerResult{}
	}

	best := make(map[crossKey]Finding, len(findings))
	sources := make(map[crossKey]map[ScannerName]struct{}, len(findings))
	order := make([]crossKey, 0, len(findings))

	// Findings without a CWE keep their position relative to each other but
	// cannot be grouped, so they are emitted as-is.
	passthrough := make([]Finding, 0)

	for _, f := range findings {
		cwe, ok := f.cwe.Get()
		if !ok {
			passthrough = append(passthrough, f)
			continue
		}

		k := crossKey{cwe: cwe, file: f.location.File(), startLine: f.location.StartLine()}

		if _, seen := best[k]; !seen {
			best[k] = f
			sources[k] = map[ScannerName]struct{}{f.source: {}}
			order = append(order, k)
			continue
		}

		sources[k][f.source] = struct{}{}
		if f.severity > best[k].severity {
			best[k] = f
		}
	}

	out := make([]Finding, 0, len(order)+len(passthrough))
	corroborated := 0
	for _, k := range order {
		out = append(out, best[k])
		if len(sources[k]) > 1 {
			corroborated++
		}
	}
	out = append(out, passthrough...)

	return CrossScannerResult{Findings: out, Corroborated: corroborated}
}
