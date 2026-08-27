package sarif

import (
	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// Codec implements ports.SarifCodec using SARIF 2.1.0.
// The zero value is ready to use.
type Codec struct{}

// New returns a ready Codec. The zero value is also valid.
func New() *Codec { return &Codec{} }

// Parse converts raw SARIF JSON into domain Findings.
func (c *Codec) Parse(data []byte) mo.Result[[]finding.Finding] {
	fs, err := parseBytes(data)
	if err != nil {
		return shared.Err[[]finding.Finding](err)
	}
	return shared.Ok(fs)
}

// Write serializes domain Findings into a SARIF 2.1.0 document.
func (c *Codec) Write(
	findings []finding.Finding,
	meta ports.SarifMetadata,
) mo.Result[[]byte] {
	data, err := writeBytes(findings, meta)
	if err != nil {
		return shared.Err[[]byte](err)
	}
	return shared.Ok(data)
}

// Merge combines multiple SARIF documents by concatenating their runs.
func (c *Codec) Merge(docs [][]byte) mo.Result[[]byte] {
	data, err := mergeBytes(docs)
	if err != nil {
		return shared.Err[[]byte](err)
	}
	return shared.Ok(data)
}
