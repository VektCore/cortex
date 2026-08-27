// Package dto defines the data transfer objects exchanged between
// the application layer and its outside callers (CLI, future HTTP API).
//
// DTOs are flat, serializable structs. They are not domain types — never
// embed an aggregate root here. Mapping happens at the boundary.
package dto
