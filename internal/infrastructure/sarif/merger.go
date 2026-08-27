package sarif

import (
	"bytes"
	"fmt"

	gosarif "github.com/owenrumney/go-sarif/v2/sarif"
)

// mergeBytes combines multiple SARIF documents by appending their runs into
// one report. The schema and version are taken from the first document.
func mergeBytes(docs [][]byte) ([]byte, error) {
	if len(docs) == 0 {
		return emptyReport()
	}

	base, err := readReport(docs[0])
	if err != nil {
		return nil, fmt.Errorf("sarif merge: parse doc 0: %w", err)
	}

	for i, doc := range docs[1:] {
		r, rErr := readReport(doc)
		if rErr != nil {
			return nil, fmt.Errorf("sarif merge: parse doc %d: %w", i+1, rErr)
		}
		for _, run := range r.Runs {
			if run != nil {
				base.AddRun(run)
			}
		}
	}

	var buf bytes.Buffer
	if err := base.Write(&buf); err != nil {
		return nil, fmt.Errorf("sarif merge: write: %w", err)
	}
	return buf.Bytes(), nil
}

func emptyReport() ([]byte, error) {
	report, err := gosarif.New(gosarif.Version210)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := report.Write(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
