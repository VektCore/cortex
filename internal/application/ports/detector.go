package ports

import (
	"context"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/domain/shared"
)

// LanguageDetector identifies which languages are present in a target
// path. Drives which scanners are activated for a scan.
type LanguageDetector interface {
	Detect(ctx context.Context, path string, exclude []string) mo.Result[[]shared.Language]
}
