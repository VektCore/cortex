// Package infrastructure contains every concrete implementation of an
// application port: scanners, publishers, notifiers, parsers, file system
// access, HTTP clients, loggers, config loaders…
//
// # Rules
//
//   - May import from domain (for value objects) and from application/ports
//     (the interfaces it implements).
//   - MUST NOT be imported by the domain or by application/usecases.
//     If you find yourself wanting to do so, you have an abstraction
//     missing — add a port instead.
//   - Each adapter lives in its own subpackage so it can be enabled or
//     disabled by a single import line in cmd/cortex.
package infrastructure
