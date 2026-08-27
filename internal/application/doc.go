// Package application contains the use cases that orchestrate the domain.
//
// # Rules
//
//   - May import from domain.
//   - MUST NOT import from infrastructure or interfaces.
//   - Defines PORTS (interfaces) for everything it needs from the outside
//     world: scanners, publishers, notifiers, clocks, repositories.
//   - Adapters in infrastructure/ implement those ports.
//
// # Layout
//
//   - ports/    — interfaces consumed by use cases (the "outbound" side).
//   - usecases/ — one file per use case: ExecuteScan, ApplyGate, Publish…
//   - services/ — coordinators that compose several use cases.
//   - dto/      — data transfer objects crossing the boundary in/out.
package application
