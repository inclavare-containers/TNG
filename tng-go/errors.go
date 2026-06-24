package tng

import (
	"errors"
	"fmt"
)

// Sentinel errors returned by the TNG SDK.
var (
	ErrNilConfig       = errors.New("tng: nil configuration")
	ErrInvalidConfig   = errors.New("tng: invalid configuration")
	ErrClientCreate    = errors.New("tng: failed to create client")
	ErrRequestFailed   = errors.New("tng: request failed")
	ErrAttestation     = errors.New("tng: attestation failed")
	ErrVerification    = errors.New("tng: verification failed")
	ErrBodyRead        = errors.New("tng: failed to read request body")
	ErrClosedTransport = errors.New("tng: transport is closed")
)

// Error wraps an FFI-level error with additional context.
type Error struct {
	Op   string // operation that failed ("NewClient", "RoundTrip")
	Msg  string // error message from Rust FFI
	Code int    // HTTP status code (0 if not an HTTP error)
}

func (e *Error) Error() string {
	if e.Code > 0 {
		return fmt.Sprintf("tng: %s: %s (HTTP %d)", e.Op, e.Msg, e.Code)
	}
	return fmt.Sprintf("tng: %s: %s", e.Op, e.Msg)
}

// Is implements errors.Is for Error.
// It matches if the target is a sentinel error (e.g., ErrRequestFailed) or
// if the target is another *Error with a matching Op field.
func (e *Error) Is(target error) bool {
	// Check against sentinel errors
	for _, sentinel := range []error{
		ErrNilConfig, ErrInvalidConfig, ErrClientCreate,
		ErrRequestFailed, ErrAttestation, ErrVerification,
		ErrBodyRead, ErrClosedTransport,
	} {
		if target == sentinel {
			return true
		}
	}
	// Check against *Error (match by Op field)
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return t.Op == "" || t.Op == e.Op
}
