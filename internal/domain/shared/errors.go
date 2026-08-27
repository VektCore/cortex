package shared

import (
	"errors"
	"fmt"
)

// DomainError is the typed error used throughout the domain layer.
//
// It carries a stable Code (machine-readable) plus a human Message, so
// callers can switch on Code without parsing the message.
type DomainError struct {
	Code    string
	Message string
	cause   error
}

// NewDomainError constructs a DomainError with no underlying cause.
func NewDomainError(code, message string) *DomainError {
	return &DomainError{Code: code, Message: message}
}

// WrapDomainError attaches an underlying cause to a DomainError.
func WrapDomainError(code, message string, cause error) *DomainError {
	return &DomainError{Code: code, Message: message, cause: cause}
}

func (e *DomainError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap supports errors.Is / errors.As.
func (e *DomainError) Unwrap() error { return e.cause }

// Sentinel errors. New codes should be added in their owning subpackage
// to avoid this file growing into a god-object.
var (
	ErrInvalidArgument = errors.New("invalid argument")
	ErrNotFound        = errors.New("not found")
	ErrInvalidState    = errors.New("invalid state")
)
