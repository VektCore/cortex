// Package ports defines the interfaces consumed by the application layer.
//
// Ports follow the Interface Segregation Principle: small, focused
// interfaces (Scanner, Publisher, Notifier, FindingRepository, Clock)
// instead of one omnibus interface. Adapters in infrastructure/ implement
// exactly the ports they need.
//
// Naming convention:
//
//	type Scanner interface { ... }            // singular, capability
//	type ScannerRegistry interface { ... }    // when a port enumerates
//	type FindingRepository interface { ... }  // "repository" suffix for persistence
//
// Every port should be:
//   - Mockable trivially (no concrete types in signatures other than
//     domain VOs and stdlib primitives).
//   - Independent of any specific tool or vendor.
package ports
