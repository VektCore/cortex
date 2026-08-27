package sarif

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	gosarif "github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// parseBytes converts raw SARIF JSON into domain Findings.
func parseBytes(data []byte) ([]finding.Finding, error) {
	report, err := readReport(data)
	if err != nil {
		return nil, fmt.Errorf("sarif parse: %w", err)
	}
	var out []finding.Finding
	for _, run := range report.Runs {
		if run == nil {
			continue
		}
		fs, runErr := parseRun(run)
		if runErr != nil {
			return nil, runErr
		}
		out = append(out, fs...)
	}
	return out, nil
}

// readReport decodes a SARIF document, retrying once on a sanitized copy.
// Every entry point uses it: a document one code path accepts and another
// rejects would lose a scanner's whole output at merge time.
func readReport(data []byte) (*gosarif.Report, error) {
	report, err := gosarif.FromBytes(data)
	if err == nil {
		return report, nil
	}

	cleaned, changed := sanitizeSARIF(data)
	if !changed {
		return nil, err
	}
	report, sanitizedErr := gosarif.FromBytes(cleaned)
	if sanitizedErr != nil {
		return nil, fmt.Errorf("%w (also after sanitizing: %w)", err, sanitizedErr)
	}
	return report, nil
}

// sanitizeSARIF works around producers that emit values the SARIF Go bindings
// reject. Two cases so far, both of which cost a whole scanner's output:
//
//   - negative "index" fields: osv-scanner writes "index": -1 to mean "no
//     index", while the bindings type it as an unsigned integer;
//   - date-only timestamps: gosec's CWE taxonomy carries
//     "releaseDateUtc": "2021-03-15", which the spec allows and the bindings
//     insist on parsing as RFC3339.
//
// Returns the cleaned document and whether anything was changed.
func sanitizeSARIF(data []byte) ([]byte, bool) {
	var doc interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return data, false
	}

	if !repairValues(doc) {
		return data, false
	}

	out, err := json.Marshal(doc)
	if err != nil {
		return data, false
	}
	return out, true
}

// unsignedFields are the SARIF properties the spec types as non-negative
// integers. Only these are dropped when negative, so a legitimate negative
// number inside a tool's own "properties" bag is never touched.
var unsignedFields = map[string]struct{}{
	"index": {}, "id": {}, "ruleIndex": {}, "parentIndex": {},
	"toolComponentIndex": {}, "occurrenceCount": {}, "order": {},
	"executionOrder": {}, "nestingLevel": {}, "threadId": {},
	"startLine": {}, "endLine": {}, "startColumn": {}, "endColumn": {},
	"byteOffset": {}, "byteLength": {}, "charOffset": {}, "charLength": {},
}

// timeFields are the SARIF properties the spec types as a timestamp. The spec
// lets a producer write just the date; the Go bindings only accept RFC3339, so
// a date-only value is widened rather than dropped — the information is
// legitimate, only its precision is lower.
var timeFields = map[string]struct{}{
	"releaseDateUtc": {}, "asOfTimeUtc": {}, "startTimeUtc": {},
	"endTimeUtc": {}, "timeUtc": {}, "lastModifiedTimeUtc": {},
	"creationTimeUtc": {}, "expirationTimeUtc": {},
}

// dateOnly matches a bare calendar date, the one shape the bindings reject.
var dateOnly = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// repairValues walks the decoded document fixing the values the bindings
// reject. Reports whether it changed any.
func repairValues(node interface{}) bool {
	switch typed := node.(type) {
	case map[string]interface{}:
		return repairObject(typed)
	case []interface{}:
		changed := false
		for _, item := range typed {
			if repairValues(item) {
				changed = true
			}
		}
		return changed
	default:
		return false
	}
}

func repairObject(object map[string]interface{}) bool {
	changed := false
	for key, value := range object {
		switch {
		case isNegativeUnsigned(key, value):
			delete(object, key)
			changed = true
		case isDateOnlyTime(key, value):
			object[key] = value.(string) + "T00:00:00Z"
			changed = true
		default:
			if repairValues(value) {
				changed = true
			}
		}
	}
	return changed
}

func isDateOnlyTime(key string, value interface{}) bool {
	if _, isTime := timeFields[key]; !isTime {
		return false
	}
	text, ok := value.(string)
	return ok && dateOnly.MatchString(text)
}

func isNegativeUnsigned(key string, value interface{}) bool {
	if _, unsigned := unsignedFields[key]; !unsigned {
		return false
	}
	number, ok := value.(float64)
	return ok && number < 0
}

func parseRun(run *gosarif.Run) ([]finding.Finding, error) {
	scannerName := finding.ScannerName("unknown")
	if run.Tool.Driver != nil && run.Tool.Driver.Name != "" {
		scannerName = finding.ScannerName(run.Tool.Driver.Name)
	}
	ruleMap := buildRuleMap(run)

	var out []finding.Finding
	for _, result := range run.Results {
		if result == nil {
			continue
		}
		f, ok, err := parseResult(result, scannerName, ruleMap)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, f)
		}
	}
	return out, nil
}

func buildRuleMap(run *gosarif.Run) map[string]*gosarif.ReportingDescriptor {
	m := make(map[string]*gosarif.ReportingDescriptor)
	if run.Tool.Driver == nil {
		return m
	}
	for _, rule := range run.Tool.Driver.Rules {
		if rule != nil {
			m[rule.ID] = rule
		}
	}
	return m
}

func parseResult(
	result *gosarif.Result,
	scannerName finding.ScannerName,
	ruleMap map[string]*gosarif.ReportingDescriptor,
) (finding.Finding, bool, error) {
	ruleID := derefStr(result.RuleID)
	if ruleID == "" {
		return finding.Finding{}, false, nil
	}

	loc, ok := extractLocation(result)
	if !ok {
		return finding.Finding{}, false, nil
	}

	rule := ruleMap[ruleID]
	sev := extractSeverity(result, rule)
	cwe := extractCWE(result, rule)

	snippet := extractSnippet(result)

	f, fErr := finding.New(finding.NewFindingInput{
		RuleID:      finding.RuleID(ruleID),
		Severity:    sev,
		Location:    loc,
		Message:     finding.Message(derefStr(result.Message.Text)),
		Source:      originalScanner(result, scannerName),
		Snippet:     snippet,
		CWE:         cwe,
		Fingerprint: storedFingerprint(result),
		SymbolName:  stringPropertyOr(result.Properties, SymbolProperty),
		Reachability: finding.ParseReachability(
			stringPropertyOr(result.Properties, ReachabilityProperty)),
	}).Get()
	if fErr != nil {
		return finding.Finding{}, false, fErr
	}
	return f, true, nil
}

// originalScanner recovers the tool that actually produced the finding. In a
// document Cortex wrote, the run's tool is "cortex", so the real scanner is
// carried in a result property.
func originalScanner(
	result *gosarif.Result, runScanner finding.ScannerName,
) finding.ScannerName {
	if name, ok := stringProperty(result.Properties, ScannerProperty); ok {
		return finding.ScannerName(name)
	}
	return runScanner
}

// storedFingerprint returns the identity Cortex recorded, or "" so the caller
// recomputes it. Recomputing is wrong for Cortex's own documents: they do not
// carry the snippet the hash is built from.
func storedFingerprint(result *gosarif.Result) finding.Fingerprint {
	if fp, ok := stringProperty(result.Properties, FingerprintProperty); ok {
		return finding.Fingerprint(fp)
	}
	return ""
}

// stringPropertyOr is stringProperty for callers that treat "absent" and
// "empty" the same.
func stringPropertyOr(props gosarif.Properties, key string) string {
	v, _ := stringProperty(props, key)
	return v
}

func stringProperty(props gosarif.Properties, key string) (string, bool) {
	if props == nil {
		return "", false
	}
	raw, ok := props[key]
	if !ok {
		return "", false
	}
	s, isString := raw.(string)
	if !isString || s == "" {
		return "", false
	}
	return s, true
}

// extractLocation reads the first physical location of a result. The bool says
// whether one was found: a result without a usable location is skipped rather
// than failing the document, because one malformed entry must not cost a whole
// scanner's output.
func extractLocation(result *gosarif.Result) (finding.Location, bool) {
	if len(result.Locations) == 0 {
		return finding.Location{}, false
	}
	physLoc := result.Locations[0].PhysicalLocation
	if physLoc == nil {
		return finding.Location{}, false
	}

	uri := ""
	if physLoc.ArtifactLocation != nil {
		uri = derefStr(physLoc.ArtifactLocation.URI)
	}
	if uri == "" {
		return finding.Location{}, false
	}
	uri = strings.TrimPrefix(uri, "./")

	startLine := 1
	endLine, startCol, endCol := 0, 0, 0
	if r := physLoc.Region; r != nil {
		if r.StartLine != nil {
			startLine = *r.StartLine
		}
		if r.EndLine != nil {
			endLine = *r.EndLine
		}
		if r.StartColumn != nil {
			startCol = *r.StartColumn
		}
		if r.EndColumn != nil {
			endCol = *r.EndColumn
		}
	}

	loc, err := finding.NewLocation(finding.LocationInput{
		File:      uri,
		StartLine: startLine,
		EndLine:   endLine,
		StartCol:  startCol,
		EndCol:    endCol,
	}).Get()
	if err != nil {
		return finding.Location{}, false // skip malformed locations
	}
	return loc, true
}

// extractSeverity derives a canonical Severity from the sources a SARIF
// document may carry, in decreasing order of trust:
//
//  1. security-severity CVSS score on the result, then on the rule
//     (GitHub/CodeQL convention, also emitted by Semgrep Pro).
//  2. result.level — set per finding.
//  3. rule.defaultConfiguration.level — where Semgrep puts it: its results
//     carry no level at all, so skipping this collapses every finding to info.
//  4. A textual severity property (issue_severity, severity) — Bandit reports
//     LOW/MEDIUM/HIGH there and omits level on some results.
//
// Nothing found means info.
func extractSeverity(result *gosarif.Result, rule *gosarif.ReportingDescriptor) shared.Severity {
	if sev, ok := cvssFromProperties(result.Properties); ok {
		return sev
	}
	if rule != nil {
		if sev, ok := cvssFromProperties(rule.Properties); ok {
			return sev
		}
	}
	if level := derefStr(result.Level); level != "" {
		return sarifLevelToSeverity(level)
	}
	if rule != nil && rule.DefaultConfiguration != nil && rule.DefaultConfiguration.Level != "" {
		return sarifLevelToSeverity(rule.DefaultConfiguration.Level)
	}
	if sev, ok := textualSeverity(result.Properties); ok {
		return sev
	}
	if rule != nil {
		if sev, ok := textualSeverity(rule.Properties); ok {
			return sev
		}
	}
	return shared.SeverityInfo
}

func cvssFromProperties(props gosarif.Properties) (shared.Severity, bool) {
	if props == nil {
		return shared.SeverityInfo, false
	}
	raw, ok := props["security-severity"]
	if !ok {
		return shared.SeverityInfo, false
	}
	return cvssToSeverity(raw)
}

// textualSeverityKeys are the property names scanners use for a word-based
// severity. Order matters: the most specific key wins.
var textualSeverityKeys = []string{"issue_severity", "severity", "problem.severity"}

func textualSeverity(props gosarif.Properties) (shared.Severity, bool) {
	if props == nil {
		return shared.SeverityInfo, false
	}
	for _, key := range textualSeverityKeys {
		raw, ok := props[key]
		if !ok {
			continue
		}
		text, isString := raw.(string)
		if !isString || strings.TrimSpace(text) == "" {
			continue
		}
		return shared.ParseSeverity(text), true
	}
	return shared.SeverityInfo, false
}

func cvssToSeverity(val interface{}) (shared.Severity, bool) {
	var score float64
	switch v := val.(type) {
	case float64:
		score = v
	case string:
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return shared.SeverityInfo, false
		}
		score = f
	default:
		return shared.SeverityInfo, false
	}
	switch {
	case score <= 0:
		// CVSS "none" — an informational finding, not a low one.
		return shared.SeverityInfo, true
	case score >= 9.0:
		return shared.SeverityCritical, true
	case score >= 7.0:
		return shared.SeverityHigh, true
	case score >= 4.0:
		return shared.SeverityMedium, true
	default:
		return shared.SeverityLow, true
	}
}

// sarifLevelToSeverity maps SARIF level strings. We call ParseSeverity because
// it already knows about "error", "warning", "note" etc.
func sarifLevelToSeverity(level string) shared.Severity {
	return shared.ParseSeverity(level)
}

// cwePattern matches a CWE id wherever it appears: Semgrep writes
// "CWE-89: Improper Neutralization…", Bandit writes "external/cwe/cwe-78",
// CodeQL writes "external/cwe/cwe-089". Requiring a "CWE" prefix — as the first
// implementation did — silently dropped every one of them.
var cwePattern = regexp.MustCompile(`(?i)cwe[-_:/ ]?0*(\d{1,5})`)

// extractCWE looks for a CWE id in the result properties, the rule properties,
// the rule name and the rule's help URI, in that order of specificity.
func extractCWE(
	result *gosarif.Result,
	rule *gosarif.ReportingDescriptor,
) mo.Option[finding.CWE] {
	candidates := propertyTags(result.Properties)
	if rule != nil {
		candidates = append(candidates, propertyTags(rule.Properties)...)
		if rule.Name != nil {
			candidates = append(candidates, *rule.Name)
		}
		candidates = append(candidates, rule.ID)
		if rule.HelpURI != nil {
			candidates = append(candidates, *rule.HelpURI)
		}
		// Last resort: the prose. Trivy names the weakness only there
		// ("contains a CWE-20: Improper Input Validation vulnerability").
		if rule.FullDescription != nil {
			candidates = append(candidates, derefStr(rule.FullDescription.Text))
		}
	}

	for _, candidate := range candidates {
		match := cwePattern.FindStringSubmatch(candidate)
		if match == nil {
			continue
		}
		cwe, err := finding.NewCWE(match[1]).Get()
		if err == nil {
			return shared.Some(cwe)
		}
	}
	return shared.None[finding.CWE]()
}

// propertyTags reads the "tags" entry of a SARIF property bag. The bag is an
// untyped map, so tags may arrive as []string or []interface{} depending on
// whether the document was decoded from JSON or built in memory.
func propertyTags(props gosarif.Properties) []string {
	raw, ok := props["tags"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func extractSnippet(result *gosarif.Result) string {
	if len(result.Locations) == 0 {
		return ""
	}
	physLoc := result.Locations[0].PhysicalLocation
	if physLoc == nil || physLoc.Region == nil {
		return ""
	}
	if physLoc.Region.Snippet != nil {
		return derefStr(physLoc.Region.Snippet.Text)
	}
	return ""
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
