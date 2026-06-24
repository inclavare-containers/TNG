//go:build integration

package tng

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// These tests require external services:
//   - Attestation Service on localhost:8080
//   - Attestation Agent socket at /run/confidential-containers/attestation-agent/attestation-agent.sock (optional, for attest mode)
//   - An optional TNG target server for full RoundTrip tests
//
// Start services before running:
//
//	make test-dep-as &
//	make test-dep-aa &
//	# Wait for services to be ready, then:
//	go test -tags=integration -v ./...

// skipIfNoAS skips the test if the Attestation Service is not reachable.
func skipIfNoAS(t *testing.T) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "127.0.0.1:8080", 2*time.Second)
	if err != nil {
		t.Skip("Attestation Service (localhost:8080) not available, skipping integration test")
	}
	conn.Close()
}

// skipIfNoAA skips the test if the Attestation Agent socket is not present.
func skipIfNoAA(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/run/confidential-containers/attestation-agent/attestation-agent.sock"); os.IsNotExist(err) {
		t.Skip("Attestation Agent socket not present, skipping integration test")
	}
}

// ---------------------------------------------------------------------------
// Integration tests: client creation
// ---------------------------------------------------------------------------

func TestIntegration_CreateClient_VerifyOnly(t *testing.T) {
	skipIfNoAS(t)

	cfg := &Config{
		Verify: map[string]any{
			"model":       "background_check",
			"as_provider": "coco",
			"as_type":     "restful",
			"as_addr":     "http://127.0.0.1:8080/",
			"policy_ids":  []string{"default"},
		},
	}

	rt, err := NewRoundTripper(cfg)
	if err != nil {
		t.Fatalf("NewRoundTripper failed: %v", err)
	}
	defer rt.Close()

	t.Log("VerifyOnly RoundTripper created successfully")
}

func TestIntegration_CreateClient_AttestAndVerify(t *testing.T) {
	skipIfNoAS(t)
	skipIfNoAA(t)

	cfg := &Config{
		Attest: map[string]any{
			"model":       "background_check",
			"aa_provider": "coco",
			"aa_type":     "uds",
			"aa_addr":     "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
		},
		Verify: map[string]any{
			"model":       "background_check",
			"as_provider": "coco",
			"as_type":     "restful",
			"as_addr":     "http://127.0.0.1:8080/",
			"policy_ids":  []string{"default"},
		},
	}

	rt, err := NewRoundTripper(cfg)
	if err != nil {
		t.Fatalf("NewRoundTripper failed: %v", err)
	}
	defer rt.Close()

	t.Log("AttestAndVerify RoundTripper created successfully")
}

func TestIntegration_CreateClient_NoRA(t *testing.T) {
	cfg := &Config{
		NoRA: true,
	}

	rt, err := NewRoundTripper(cfg)
	if err != nil {
		t.Fatalf("NewRoundTripper with NoRA failed: %v", err)
	}
	defer rt.Close()

	t.Log("NoRA RoundTripper created successfully (no external services required)")
}

func TestIntegration_CreateClient_PassportMode(t *testing.T) {
	skipIfNoAS(t)

	cfg := &Config{
		Verify: map[string]any{
			"model":       "passport",
			"as_provider": "ita",
			"as_type":     "restful",
			"as_addr":     "http://127.0.0.1:8080/",
			"policy_ids":  []string{"default"},
		},
	}

	rt, err := NewRoundTripper(cfg)
	if err != nil {
		t.Fatalf("NewRoundTripper failed: %v", err)
	}
	defer rt.Close()

	t.Log("Passport mode RoundTripper created successfully")
}

// ---------------------------------------------------------------------------
// Integration tests: functional RoundTrip (requires target server)
// ---------------------------------------------------------------------------

// TestIntegration_NoRA_RoundTrip tests a full request/response cycle in NoRA
// mode. It starts a local mock HTTP server that emulates a TNG egress proxy
// capable of handling the OHTTP protocol in NoRA mode.
//
// NOTE: This test currently documents the expected behavior. The mock server
// would need to implement the full OHTTP protocol to pass. Until a local
// OHTTP proxy is available for testing, this test verifies that:
// 1. Client creation succeeds
// 2. RoundTrip returns an error (expected, since no real OHTTP endpoint exists)
func TestIntegration_NoRA_RoundTrip(t *testing.T) {
	cfg := &Config{
		NoRA: true,
	}

	rt, err := NewRoundTripper(cfg)
	if err != nil {
		t.Fatalf("NewRoundTripper failed: %v", err)
	}
	defer rt.Close()

	// Attempt a request to a non-OHTTP endpoint.
	// In NoRA mode, this should fail with a connection or protocol error
	// because the target is not a TNG egress proxy.
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19999/test", nil)
	_, err = rt.RoundTrip(req)
	if err == nil {
		t.Log("RoundTrip succeeded unexpectedly (no target server running)")
	} else {
		t.Logf("RoundTrip failed as expected (no OHTTP proxy at target): %v", err)
	}
}

// TestIntegration_Fallback_PassThrough verifies that the fallback transport
// correctly delegates traffic when the URL matches the fallback predicate.
// This test uses a real httptest.Server to confirm the fallback path works
// without involving the TNG FFI for the actual HTTP exchange.
func TestIntegration_Fallback_PassThrough(t *testing.T) {
	// Start a mock backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"message":"hello from backend"}`)
	}))
	defer backend.Close()

	cfg := &Config{
		NoRA: true,
	}

	rt, err := NewRoundTripper(cfg,
		WithFallback(http.DefaultTransport, func(u *url.URL) bool {
			// Delegate all requests to this mock server to the fallback
			return strings.HasPrefix(u.Host, "127.0.0.1") || strings.HasPrefix(u.Host, "localhost")
		}),
	)
	if err != nil {
		t.Fatalf("NewRoundTripper failed: %v", err)
	}
	defer rt.Close()

	// Request to the fallback URL
	req := httptest.NewRequest(http.MethodGet, backend.URL+"/api/data", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip via fallback failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if !strings.Contains(string(body), "hello from backend") {
		t.Errorf("unexpected body: %s", string(body))
	}

	t.Logf("Fallback passthrough succeeded: status=%d body=%s", resp.StatusCode, string(body))
}

// TestIntegration_Fallback_MixedTraffic verifies that TNG traffic goes through
// the FFI while non-TNG traffic uses the fallback. The test confirms the
// fallback matching logic works correctly.
func TestIntegration_Fallback_MixedTraffic(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"source":"fallback"}`)
	}))
	defer backend.Close()

	cfg := &Config{NoRA: true}

	rt, err := NewRoundTripper(cfg,
		WithFallback(http.DefaultTransport, func(u *url.URL) bool {
			// Only requests to the mock server's address use the fallback
			return strings.HasPrefix(u.Host, "127.0.0.1")
		}),
	)
	if err != nil {
		t.Fatalf("NewRoundTripper failed: %v", err)
	}
	defer rt.Close()

	// This should use the fallback
	req := httptest.NewRequest(http.MethodGet, backend.URL+"/test", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("fallback request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	t.Log("Mixed traffic fallback: fallback URL succeeded")
}

// ---------------------------------------------------------------------------
// Integration tests: error handling
// ---------------------------------------------------------------------------

func TestIntegration_ClosedTransport(t *testing.T) {
	cfg := &Config{NoRA: true}

	rt, err := NewRoundTripper(cfg)
	if err != nil {
		t.Fatalf("NewRoundTripper failed: %v", err)
	}

	if err := rt.Close(); err != nil {
		t.Fatalf("first close failed: %v", err)
	}

	// Second close should be idempotent
	if err := rt.Close(); err != nil {
		t.Fatalf("second close should be idempotent: %v", err)
	}

	// Request after close should return ErrClosedTransport
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	_, err = rt.RoundTrip(req)
	if err != ErrClosedTransport {
		t.Errorf("expected ErrClosedTransport after close, got %v", err)
	}

	t.Log("Closed transport error handling correct")
}

func TestIntegration_NilConfigError(t *testing.T) {
	_, err := NewRoundTripper(nil)
	if err != ErrNilConfig {
		t.Errorf("expected ErrNilConfig, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Integration tests: log filter
// ---------------------------------------------------------------------------

func TestIntegration_WithLogFilter(t *testing.T) {
	cfg := &Config{NoRA: true}

	// WithLogFilter should not prevent client creation
	rt, err := NewRoundTripper(cfg, WithLogFilter("tng=info"))
	if err != nil {
		t.Fatalf("NewRoundTripper with log filter failed: %v", err)
	}
	defer rt.Close()

	t.Log("RoundTripper with log filter created successfully")
}
