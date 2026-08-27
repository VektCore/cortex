package shared

import "time"

// Clock abstracts the source of "now" so that domain code remains
// deterministic under test. Production wires time.Now via the SystemClock;
// tests inject a fake clock that returns a fixed value.
//
// The domain MUST NOT call time.Now() directly — every aggregate that
// needs the current instant receives a Clock.
type Clock interface {
	Now() time.Time
}

// SystemClock is the production implementation backed by time.Now().
type SystemClock struct{}

// Now returns the current wall-clock time.
func (SystemClock) Now() time.Time { return time.Now() }
