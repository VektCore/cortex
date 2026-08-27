package sarif_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
	infrasarif "github.com/vektcore/cortex/internal/infrastructure/sarif"
)

func readTestData(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("_testdata", name))
	require.NoError(t, err)
	return data
}

// ---------- Parse ----------

func TestCodec_Parse_SemgrepSARIF(t *testing.T) {
	t.Parallel()
	codec := infrasarif.New()
	data := readTestData(t, "semgrep_sqli.sarif")

	findings, err := codec.Parse(data).Get()
	require.NoError(t, err)
	require.Len(t, findings, 3)

	// CWE-89 result should be critical (security-severity 9.8)
	sqli := findByFile(t, findings, "app/models.py")
	assert.Equal(t, shared.SeverityCritical, sqli.Severity())
	assert.Equal(t, finding.RuleID("python.sqlalchemy.security.sqli-detected.sqli-detected"), sqli.RuleID())
	cwe, ok := sqli.CWE().Get()
	assert.True(t, ok)
	assert.Equal(t, "CWE-89", cwe.String())
	assert.Equal(t, finding.ScannerName("semgrep"), sqli.Source())
	assert.Equal(t, 42, sqli.Location().StartLine())
	assert.Equal(t, "app/models.py", sqli.Location().File())

	// Hardcoded password should be high (security-severity 7.5)
	pwd := findByFile(t, findings, "app/config.py")
	assert.Equal(t, shared.SeverityHigh, pwd.Severity())
	pwdCWE, ok := pwd.CWE().Get()
	assert.True(t, ok)
	assert.Equal(t, "CWE-798", pwdCWE.String())

	// eval() should be medium (security-severity 5.0)
	eval := findByFile(t, findings, "app/views.py")
	assert.Equal(t, shared.SeverityMedium, eval.Severity())
}

func TestCodec_Parse_MinimalSARIF(t *testing.T) {
	t.Parallel()
	codec := infrasarif.New()
	data := readTestData(t, "minimal.sarif")

	findings, err := codec.Parse(data).Get()
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCodec_Parse_InvalidJSON(t *testing.T) {
	t.Parallel()
	codec := infrasarif.New()

	_, err := codec.Parse([]byte("{not valid json")).Get()
	assert.Error(t, err)
}

func TestCodec_Parse_SkipsResultsWithNoLocation(t *testing.T) {
	t.Parallel()
	codec := infrasarif.New()
	noLoc := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "x"}},
			"results": [
				{"ruleId": "rule1", "message": {"text": "no-loc"}, "level": "error"}
			]
		}]
	}`)

	findings, err := codec.Parse(noLoc).Get()
	require.NoError(t, err)
	assert.Empty(t, findings, "results without location must be skipped gracefully")
}

// ---------- Write ----------

func TestCodec_Write_ProducesValidSARIF(t *testing.T) {
	t.Parallel()
	codec := infrasarif.New()
	f := mkFinding(t, "src/main.go", shared.SeverityHigh, "gosec", "CWE-89")

	data, err := codec.Write([]finding.Finding{f}, ports.SarifMetadata{
		Tool:    "cortex",
		Version: "0.1.0",
	}).Get()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Round-trip: parse what we just wrote
	fs, parseErr := codec.Parse(data).Get()
	require.NoError(t, parseErr)
	require.Len(t, fs, 1)

	rt := fs[0]
	assert.Equal(t, f.RuleID(), rt.RuleID())
	assert.Equal(t, f.Severity(), rt.Severity())
	assert.Equal(t, f.Location().File(), rt.Location().File())
	assert.Equal(t, f.Location().StartLine(), rt.Location().StartLine())
}

func TestCodec_Write_EmptyFindings(t *testing.T) {
	t.Parallel()
	codec := infrasarif.New()

	data, err := codec.Write(nil, ports.SarifMetadata{
		Tool:    "cortex",
		Version: "0.1.0",
	}).Get()
	require.NoError(t, err)
	assert.NotEmpty(t, data, "empty findings still produces valid SARIF envelope")
}

// ---------- Merge ----------

func TestCodec_Merge_CombinesRuns(t *testing.T) {
	t.Parallel()
	codec := infrasarif.New()

	doc1, _ := codec.Write(
		[]finding.Finding{mkFinding(t, "a.py", shared.SeverityHigh, "semgrep", "")},
		ports.SarifMetadata{Tool: "cortex", Version: "0.1.0"},
	).Get()
	doc2, _ := codec.Write(
		[]finding.Finding{mkFinding(t, "b.py", shared.SeverityMedium, "bandit", "")},
		ports.SarifMetadata{Tool: "cortex", Version: "0.1.0"},
	).Get()

	merged, err := codec.Merge([][]byte{doc1, doc2}).Get()
	require.NoError(t, err)

	// The merged document must have 2 runs, each with 1 result
	var probe struct {
		Runs []struct {
			Results []interface{} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, unmarshalJSON(merged, &probe))
	require.Len(t, probe.Runs, 2)
	assert.Len(t, probe.Runs[0].Results, 1)
	assert.Len(t, probe.Runs[1].Results, 1)
}

func TestCodec_Merge_EmptySlice(t *testing.T) {
	t.Parallel()
	codec := infrasarif.New()

	data, err := codec.Merge(nil).Get()
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

func TestCodec_Merge_InvalidDoc(t *testing.T) {
	t.Parallel()
	codec := infrasarif.New()

	_, err := codec.Merge([][]byte{[]byte("not sarif")}).Get()
	assert.Error(t, err)
}

// ---------- Helpers ----------

func mkFinding(t *testing.T, file string, sev shared.Severity, source, cweStr string) finding.Finding {
	t.Helper()
	loc, err := finding.NewLocation(finding.LocationInput{File: file, StartLine: 10}).Get()
	require.NoError(t, err)

	in := finding.NewFindingInput{
		RuleID:   finding.RuleID("test.rule"),
		Severity: sev,
		Location: loc,
		Message:  finding.Message("test message"),
		Source:   finding.ScannerName(source),
		Snippet:  file + sev.String(),
	}
	if cweStr != "" {
		cwe, cweErr := finding.NewCWE(cweStr).Get()
		require.NoError(t, cweErr)
		in.CWE = shared.Some(cwe)
	}

	f, fErr := finding.New(in).Get()
	require.NoError(t, fErr)
	return f
}

func findByFile(t *testing.T, findings []finding.Finding, file string) finding.Finding {
	t.Helper()
	for _, f := range findings {
		if f.Location().File() == file {
			return f
		}
	}
	t.Fatalf("no finding for file %q", file)
	return finding.Finding{}
}

func unmarshalJSON(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// gosec's CWE taxonomy carries "releaseDateUtc": "2021-03-15" — a date without
// a time, which SARIF permits and the Go bindings reject. Parsing has to
// survive it: rejecting the document loses gosec's entire output, which is
// every Go repository's Go-specific coverage.
func TestCodec_Parse_TaxonomyWithDateOnlyTimestamp(t *testing.T) {
	t.Parallel()

	findings, err := infrasarif.New().Parse(readTestData(t, "gosec_taxonomy_dateonly.sarif")).Get()

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "G404", findings[0].RuleID().String())
	assert.Equal(t, "internal/token/token.go", findings[0].Location().File())
}

// GitHub Code Scanning validates the document strictly and rejects the whole
// upload when a rule's shortDescription is null — which is what the bindings
// serialise when it is left unset, because the field carries no omitempty.
func TestCodec_Write_RulesCarryAShortDescription(t *testing.T) {
	t.Parallel()

	findings := []finding.Finding{
		mkFindingWithMessage(t,
			"Possible SQL injection vector through string-based query construction. Review it."),
	}

	raw, err := infrasarif.New().Write(findings, ports.SarifMetadata{Tool: "cortex"}).Get()
	require.NoError(t, err)

	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID               string `json:"id"`
						ShortDescription *struct {
							Text string `json:"text"`
						} `json:"shortDescription"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.NotEmpty(t, doc.Runs[0].Tool.Driver.Rules)

	rule := doc.Runs[0].Tool.Driver.Rules[0]
	require.NotNil(t, rule.ShortDescription,
		"a null shortDescription makes Code Scanning reject the entire document")
	assert.Equal(t, "Possible SQL injection vector through string-based query construction",
		rule.ShortDescription.Text,
		"one sentence, one line — not the whole message")
}

// mkFindingWithMessage builds a finding whose message drives the rule's
// shortDescription.
func mkFindingWithMessage(t *testing.T, message string) finding.Finding {
	t.Helper()

	loc, err := finding.NewLocation(finding.LocationInput{File: "app/db.py", StartLine: 42}).Get()
	require.NoError(t, err)

	f, err := finding.New(finding.NewFindingInput{
		RuleID:   finding.RuleID("B608"),
		Severity: shared.SeverityHigh,
		Location: loc,
		Message:  finding.Message(message),
		Source:   finding.ScannerName("bandit"),
		Snippet:  "query = 'SELECT ' + x",
	}).Get()
	require.NoError(t, err)
	return f
}
