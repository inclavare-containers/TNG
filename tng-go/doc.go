// Package tng provides an http.RoundTripper implementation for the
// Trusted Network Gateway (TNG). It transparently encrypts HTTP requests
// via Oblivious HTTP (OHTTP) and handles remote attestation through
// a Rust FFI layer.
//
// # Basic Usage
//
//	rt, err := tng.NewRoundTripper(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer rt.Close()
//
//	client := &http.Client{Transport: rt}
//	resp, err := client.Get("http://target:30001/api/data")
//
// # Configuration
//
// The SDK supports three modes:
//
//   - Verify-only: Verify server attestation (client acts as verifier)
//   - Attest-and-verify: Mutual attestation (client attests and verifies)
//   - NoRA: No remote attestation (testing/development only)
//
// See Config for the full configuration format. Note that the "model"
// field must use snake_case (e.g., "background_check", "passport") to
// match the Rust serde serialization format.
//
// # Streaming
//
// Use WithStreaming() for SSE or large response bodies:
//
//	rt, _ := tng.NewRoundTripper(cfg, tng.WithStreaming())
//
// # Fallback
//
// Use WithFallback() to delegate non-TNG URLs to a standard transport:
//
//	rt, _ := tng.NewRoundTripper(cfg, tng.WithFallback(http.DefaultTransport, func(u *url.URL) bool {
//	    return u.Host != "target:30001"
//	}))
//
// # Error Handling
//
// All errors are *tng.Error with Op and Msg fields. Use errors.Is
// to match sentinel errors (ErrNilConfig, ErrClosedTransport, etc.).
//
// # Requirements
//
// The SDK requires CGO and the pre-compiled Rust FFI library
// (libtng_go_ffi.so). Build with:
//
//	make go-build
package tng
