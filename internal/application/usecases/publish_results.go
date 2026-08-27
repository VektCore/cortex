package usecases

import (
	"context"
	"fmt"
	"sync"

	"github.com/vektcore/cortex/internal/application/dto"
	"github.com/vektcore/cortex/internal/application/ports"
)

// PublishResults fans a single SARIF document out to one or more
// publishers in parallel. A failed publisher is reported in the
// response but never aborts the overall use case.
type PublishResults struct {
	publishers map[string]ports.Publisher
	logger     ports.Logger
}

// PublishResultsDeps is the constructor parameter struct.
type PublishResultsDeps struct {
	Publishers map[string]ports.Publisher
	Logger     ports.Logger
}

// NewPublishResults wires the use case.
func NewPublishResults(d PublishResultsDeps) *PublishResults {
	return &PublishResults{publishers: d.Publishers, logger: d.Logger}
}

// Execute fans out to publishers concurrently.
func (uc *PublishResults) Execute(
	ctx context.Context, req dto.PublishResultsRequest,
) dto.PublishResultsResponse {
	targets := req.Targets
	if len(targets) == 0 {
		targets = make([]string, 0, len(uc.publishers))
		for name := range uc.publishers {
			targets = append(targets, name)
		}
	}

	response := dto.PublishResultsResponse{
		Errors: make(map[string]error),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, name := range targets {
		pub, ok := uc.publishers[name]
		if !ok {
			mu.Lock()
			response.Errors[name] = fmt.Errorf("publisher %q not configured", name)
			mu.Unlock()
			continue
		}
		wg.Add(1)
		go func(p ports.Publisher) {
			defer wg.Done()
			receipt, err := p.Publish(ctx, ports.PublishRequest{
				ScanID:   req.Scan.ID(),
				Revision: req.Scan.Revision(),
				Findings: req.Findings,
				SARIF:    req.SARIF,
				Metadata: req.Metadata,
			}).Get()

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				uc.logger.Warn("publisher failed",
					ports.F("publisher", p.Name()),
					ports.F("error", err.Error()))
				response.Errors[p.Name()] = err
				return
			}
			response.Receipts = append(response.Receipts, receipt)
		}(pub)
	}

	wg.Wait()
	return response
}
