package shared

import "github.com/samber/mo"

// Result and Option are the two effect types used across the domain.
//
// Convention:
//
//   - Functions that may fail return mo.Result[T] — never (T, error).
//   - Functions that may return "nothing" return mo.Option[T] — never
//     (T, bool) and never *T as a hidden absence signal.
//   - Use Some/None to construct Option[T]; Ok/Err to construct Result[T].
//
// These helpers exist so domain code does not need to import samber/mo
// in every file, and so that one day swapping the underlying library
// is a one-package change.

// Some lifts a value into mo.Option[T] as a present value.
func Some[T any](v T) mo.Option[T] { return mo.Some(v) }

// None returns an empty mo.Option[T].
func None[T any]() mo.Option[T] { return mo.None[T]() }

// Ok lifts a value into mo.Result[T] as a success.
func Ok[T any](v T) mo.Result[T] { return mo.Ok(v) }

// Err lifts an error into mo.Result[T] as a failure.
func Err[T any](err error) mo.Result[T] { return mo.Err[T](err) }
