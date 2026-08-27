package ports

import (
	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/scan"
)

// SarifMetadata is what the writer needs to populate the SARIF
// "tool"/"run" header.
type SarifMetadata struct {
	Tool     string
	Version  string
	Revision scan.Revision
}

// SarifCodec hides the SARIF schema behind a domain-friendly interface.
// Implementations live in infrastructure/sarif.
type SarifCodec interface {
	Parse(data []byte) mo.Result[[]finding.Finding]
	Write(findings []finding.Finding, meta SarifMetadata) mo.Result[[]byte]
	Merge(docs [][]byte) mo.Result[[]byte]
}
