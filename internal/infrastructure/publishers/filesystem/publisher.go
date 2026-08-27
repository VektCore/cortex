// Package filesystem publishes scan results to the local filesystem.
// It writes one SARIF file per scan execution, useful for archiving results
// and as input to downstream tools.
package filesystem

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// Publisher implements ports.Publisher by writing SARIF to outputDir.
type Publisher struct {
	outputDir string
}

// New returns a Publisher that writes to outputDir.
// Defaults to "results/" when empty.
func New(outputDir string) *Publisher {
	if outputDir == "" {
		outputDir = "results/"
	}
	return &Publisher{outputDir: outputDir}
}

func (p *Publisher) Name() string { return "filesystem" }

// Publish writes req.SARIF to <outputDir>/<scanID>.sarif.
func (p *Publisher) Publish(
	_ context.Context,
	req ports.PublishRequest,
) mo.Result[ports.PublishReceipt] {
	if err := os.MkdirAll(p.outputDir, 0o755); err != nil {
		return shared.Err[ports.PublishReceipt](
			fmt.Errorf("filesystem publisher: mkdir %q: %w", p.outputDir, err))
	}

	name := req.ScanID.String()
	if name == "" {
		name = "scan"
	}
	outPath := filepath.Join(p.outputDir, name+".sarif")

	if err := os.WriteFile(outPath, req.SARIF, 0o600); err != nil {
		return shared.Err[ports.PublishReceipt](
			fmt.Errorf("filesystem publisher: write %q: %w", outPath, err))
	}

	return shared.Ok(ports.PublishReceipt{
		Publisher: "filesystem",
		Reference: outPath,
	})
}
