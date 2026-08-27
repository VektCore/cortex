// Cortex — multi-language SAST engine for CI/CD pipelines.
//
// This is the only entrypoint. It wires the CLI and delegates to the
// interfaces/cli package. Keep main thin: no business logic here.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/vektcore/cortex/internal/interfaces/cli"
)

func main() {
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt, syscall.SIGTERM,
	)
	defer cancel()

	os.Exit(cli.Execute(ctx, os.Args[1:]))
}
