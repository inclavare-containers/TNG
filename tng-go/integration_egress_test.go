//go:build integration

package tng

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// egressProcess manages a shared TNG egress instance.
type egressProcess struct {
	process     *exec.Cmd
	controlPort int
}

// sharedTestEnv holds infrastructure shared across all E2E tests
// to avoid iptables chain conflicts and port binding delays.
var sharedTestEnv struct {
	mu      sync.Mutex
	once    sync.Once
	egress  *egressProcess
	backends map[int]*http.Server
}

// checkNoCompetingTng ensures no other TNG egress instances are running,
// as TNG doesn't support multiple instances in the same network namespace.
// If competing instances are found, they are killed.
func checkNoCompetingTng(t *testing.T) {
	t.Helper()
	// Kill any non-test-dep tng launch processes
	// Note: Don't kill TNG_BINARY as that might be our own binary
	if tngBin := os.Getenv("TNG_BINARY"); tngBin != "" {
		// Only kill other tng processes, not our binary
		exec.Command("sh", "-c", fmt.Sprintf("pkill -9 -f 'tng launch' 2>/dev/null || true")).Run()
	} else {
		exec.Command("sh", "-c", "pkill -9 -f 'target/debug/tng' 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "pkill -9 -f 'target/release/tng' 2>/dev/null || true").Run()
	}

	// Clean up any leftover iptables rules (simplified - just flush and delete chains)
	for id := 0; id <= 5; id++ {
		chain := fmt.Sprintf("TNG_EGRESS_%d", id)
		_ = exec.Command("sh", "-c", fmt.Sprintf("iptables -t nat -F %s 2>/dev/null || true", chain)).Run()
		_ = exec.Command("sh", "-c", fmt.Sprintf("iptables -t nat -X %s 2>/dev/null || true", chain)).Run()
	}

	time.Sleep(100 * time.Millisecond) // Brief pause for cleanup
}

// setupSharedEnv starts a single egress and all backends.
// Called by each test; only the first caller does actual work.
func setupSharedEnv(t *testing.T) {
	t.Helper()
	sharedTestEnv.mu.Lock()
	defer sharedTestEnv.mu.Unlock()

	sharedTestEnv.once.Do(func() {
		checkNoCompetingTng(t)
		startEgressAndBackends(t)
	})
}

func startEgressAndBackends(t *testing.T) {
	workspaceDir := findWorkspaceDir(t)
	controlPort := findFreePort(t)
	capturePorts := []int{30001, 30002, 30003}

	// Build config with all three capture ports
	captureDst := make([]map[string]any, len(capturePorts))
	for i, p := range capturePorts {
		captureDst[i] = map[string]any{"port": p}
	}

	config := map[string]any{
		"add_egress": []map[string]any{
			{
				"netfilter": map[string]any{
					"capture_dst":           captureDst,
					"capture_local_traffic": true,
				},
				"ohttp": map[string]any{},
				"no_ra": true,
			},
		},
		"control_interface": map[string]any{
			"restful": map[string]any{
				"host": "127.0.0.1",
				"port": controlPort,
			},
		},
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("failed to marshal egress config: %v", err)
	}

	t.Logf("Starting shared TNG egress (ports %v, control=%d)", capturePorts, controlPort)

	// Clean up leftover iptables rules from previous runs
	cleanupIptables(t)

	// Start egress
	tngBinary := workspaceDir + "/target/release/tng"
	var cmd *exec.Cmd
	if _, err := os.Stat(tngBinary); err == nil {
		cmd = exec.Command(tngBinary, "launch", "--config-content", string(configJSON))
	} else {
		cmd = exec.Command("cargo", "run", "-p", "tng", "--", "launch", "--config-content", string(configJSON))
		cmd.Dir = workspaceDir
	}
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start egress: %v", err)
	}

	ep := &egressProcess{process: cmd, controlPort: controlPort}

	// Wait for readiness
	readyURL := fmt.Sprintf("http://127.0.0.1:%d/readyz", controlPort)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(readyURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			time.Sleep(200 * time.Millisecond)
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
			t.Fatalf("egress process exited unexpectedly: %v", cmd.Wait())
		}
		time.Sleep(200 * time.Millisecond)
	}

	t.Logf("Shared TNG egress is ready (control port %d)", controlPort)

	// Start backends
	sharedTestEnv.backends = make(map[int]*http.Server)

	// Backend for port 30001 — RoundTrip test
	startBackendOnPort(t, 30001, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/data" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"message":"hello from OHTTP egress"}`)
	}))

	// Backend for port 30002 — POST test
	startBackendOnPort(t, 30002, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"echo":"%s"}`, string(body))
	}))

	// Backend for port 30003 — Streaming SSE test
	startBackendOnPort(t, 30003, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for i := 0; i < 3; i++ {
			fmt.Fprintf(w, "data: event %d via OHTTP\n\n", i)
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))

	sharedTestEnv.egress = ep
}

func cleanupIptables(t *testing.T) {
	t.Helper()
	for id := 0; id <= 5; id++ {
		chain := fmt.Sprintf("TNG_EGRESS_%d", id)
		for i := 0; i < 5; i++ {
			exec.Command("sh", "-c", fmt.Sprintf("iptables -t nat -D PREROUTING -p tcp -j %s 2>/dev/null || true", chain)).Run()
			exec.Command("sh", "-c", fmt.Sprintf("iptables -t nat -D OUTPUT -p tcp -j %s 2>/dev/null || true", chain)).Run()
		}
		exec.Command("sh", "-c", fmt.Sprintf("iptables -t nat -F %s 2>/dev/null || true", chain)).Run()
		exec.Command("sh", "-c", fmt.Sprintf("iptables -t nat -X %s 2>/dev/null || true", chain)).Run()
	}
}

func findFreePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

func startBackendOnPort(t *testing.T, port int, handler http.Handler) {
	t.Helper()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to listen on port %d: %v", port, err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)
	// Don't register t.Cleanup — backends live for the entire test session
	sharedTestEnv.backends[port] = srv
}

// ---------------------------------------------------------------------------
// E2E Integration tests: real OHTTP request through TNG egress
// All tests share a single egress + backends to avoid iptables conflicts.
// ---------------------------------------------------------------------------

// TestE2E_NoRA_RoundTrip verifies a full OHTTP GET request/response cycle.
func TestE2E_NoRA_RoundTrip(t *testing.T) {
	setupSharedEnv(t)
	capturePort := 30001

	cfg := &Config{NoRA: true}
	rt, err := NewRoundTripper(cfg)
	if err != nil {
		t.Fatalf("NewRoundTripper failed: %v", err)
	}
	defer rt.Close()

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("http://127.0.0.1:%d/api/data", capturePort), nil)
	req.Host = fmt.Sprintf("127.0.0.1:%d", capturePort)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	if !strings.Contains(string(body), "hello from OHTTP egress") {
		t.Errorf("unexpected body: %s", string(body))
	}

	t.Logf("E2E OHTTP RoundTrip succeeded: status=%d body=%s", resp.StatusCode, string(body))
}

// TestE2E_NoRA_POST verifies POST body is correctly forwarded through OHTTP.
func TestE2E_NoRA_POST(t *testing.T) {
	setupSharedEnv(t)
	capturePort := 30002

	cfg := &Config{NoRA: true}
	rt, err := NewRoundTripper(cfg)
	if err != nil {
		t.Fatalf("NewRoundTripper failed: %v", err)
	}
	defer rt.Close()

	reqBody := strings.NewReader(`{"test":"payload"}`)
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d/echo", capturePort), reqBody)
	req.Header.Set("Content-Type", "application/json")

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("POST RoundTrip failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	if !strings.Contains(string(body), "payload") {
		t.Errorf("expected echo of payload, got: %s", string(body))
	}

	t.Logf("E2E OHTTP POST succeeded: body=%s", string(body))
}

// TestE2E_NoRA_StreamingSSE verifies streaming SSE responses through OHTTP.
func TestE2E_NoRA_StreamingSSE(t *testing.T) {
	setupSharedEnv(t)
	capturePort := 30003

	cfg := &Config{NoRA: true}
	rt, err := NewRoundTripper(cfg)
	if err != nil {
		t.Fatalf("NewRoundTripper with streaming failed: %v", err)
	}
	defer rt.Close()

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("http://127.0.0.1:%d/events", capturePort), nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("streaming RoundTrip failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	lineCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			lineCount++
		}
	}
	if lineCount != 3 {
		t.Errorf("expected 3 SSE data lines, got %d", lineCount)
	}

	t.Logf("E2E OHTTP streaming SSE succeeded: %d events", lineCount)
}

// TestE2E_NoRA_AttestationInfo verifies that GetAttestationInfo can be called
// without panicking after a successful RoundTrip in NoRA mode.
// In NoRA mode, attestation info may be nil or present — we just verify the function works.
func TestE2E_NoRA_AttestationInfo(t *testing.T) {
	setupSharedEnv(t)
	capturePort := 30001

	cfg := &Config{NoRA: true}
	rt, err := NewRoundTripper(cfg)
	if err != nil {
		t.Fatalf("NewRoundTripper failed: %v", err)
	}
	defer rt.Close()

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("http://127.0.0.1:%d/api/data", capturePort), nil)
	req.Host = fmt.Sprintf("127.0.0.1:%d", capturePort)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Verify response headers are accessible
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		t.Error("expected Content-Type header to be accessible")
	}

	// Call GetAttestationInfo — should not panic in NoRA mode
	// Attestation info may be nil or present; we just verify the function works
	info := GetAttestationInfo(resp)
	if info != nil {
		t.Logf("Attestation info present: token=%s, as_provider=%s", info.Token, info.ASProvider)
	} else {
		t.Log("Attestation info is nil (expected in NoRA mode)")
	}

	t.Logf("E2E NoRA AttestationInfo test succeeded")
}

// TestE2E_NoRA_MultipleSequentialRequests verifies that the TNG proxy
// handles multiple sequential connections correctly through the same RoundTripper.
func TestE2E_NoRA_MultipleSequentialRequests(t *testing.T) {
	setupSharedEnv(t)
	capturePort := 30001

	cfg := &Config{NoRA: true}
	rt, err := NewRoundTripper(cfg)
	if err != nil {
		t.Fatalf("NewRoundTripper failed: %v", err)
	}
	defer rt.Close()

	// Make 5 sequential GET requests
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet,
			fmt.Sprintf("http://127.0.0.1:%d/api/data", capturePort), nil)
		req.Host = fmt.Sprintf("127.0.0.1:%d", capturePort)

		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip request %d failed: %v", i+1, err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("request %d: expected status 200, got %d", i+1, resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("request %d: failed to read body: %v", i+1, err)
		}

		if !strings.Contains(string(body), "hello from OHTTP egress") {
			t.Errorf("request %d: unexpected body: %s", i+1, string(body))
		}

		t.Logf("Request %d succeeded: status=%d", i+1, resp.StatusCode)
	}

	t.Logf("E2E NoRA MultipleSequentialRequests test succeeded: 5 requests completed")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func findWorkspaceDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	for i := 0; i < 10; i++ {
		data, err := os.ReadFile(filepath.Join(dir, "Cargo.toml"))
		if err == nil && bytes.Contains(data, []byte("workspace")) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not find workspace Cargo.toml")
	return ""
}
