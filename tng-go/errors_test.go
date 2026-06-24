package tng

import (
	"errors"
	"testing"
)

func TestErrorIs_Sentinel(t *testing.T) {
	err := &Error{Op: "RoundTrip", Msg: "connection refused"}

	// Should match any sentinel error
	for _, sentinel := range []error{
		ErrNilConfig, ErrInvalidConfig, ErrClientCreate,
		ErrRequestFailed, ErrAttestation, ErrVerification,
		ErrBodyRead, ErrClosedTransport,
	} {
		if !errors.Is(err, sentinel) {
			t.Errorf("Error should match sentinel %v", sentinel)
		}
	}
}

func TestErrorIs_ErrorOp(t *testing.T) {
	err := &Error{Op: "RoundTrip", Msg: "connection refused"}

	// Match by Op
	target := &Error{Op: "RoundTrip"}
	if !errors.Is(err, target) {
		t.Error("Error should match target with same Op")
	}

	// No match by different Op
	target2 := &Error{Op: "NewRoundTripper"}
	if errors.Is(err, target2) {
		t.Error("Error should not match target with different Op")
	}

	// Empty Op matches any
	target3 := &Error{Op: ""}
	if !errors.Is(err, target3) {
		t.Error("Error should match target with empty Op")
	}

	// Non-Error target returns false
	if errors.Is(err, errors.New("tng: some error")) {
		t.Error("Error should not match non-Error target")
	}
}
