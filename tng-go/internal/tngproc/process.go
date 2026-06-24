package tngproc

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Process manages a TNG subprocess.
type Process struct {
	cmd       *exec.Cmd
	proxyPort int
	logFile   *os.File
	cfgPath   string
}

// New spawns a TNG subprocess with the given config.
// It finds the binary, writes a temp config, starts the process,
// and waits for the http_proxy to be ready.
func New(cfg *IngressConfig) (*Process, error) {
	// Find TNG binary
	binPath, err := findTngBinary()
	if err != nil {
		return nil, err
	}

	// Allocate free port
	port, err := findFreePort()
	if err != nil {
		return nil, fmt.Errorf("failed to find free port: %w", err)
	}

	// Build and write config to temp file
	cfgPath, err := writeTempConfig(port, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to write config: %w", err)
	}

	// Create log file for debugging
	logFile, err := os.CreateTemp("", "tng-sdk-*.log")
	if err != nil {
		os.Remove(cfgPath)
		return nil, fmt.Errorf("failed to create log file: %w", err)
	}

	// Start TNG subprocess
	cmd := exec.Command(binPath, "launch", "--config-file", cfgPath)
	cmd.Stdout = logFile  // Redirect stdout to log file for debugging
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		logFile.Close()
		os.Remove(cfgPath)
		return nil, fmt.Errorf("failed to start tng: %w", err)
	}

	p := &Process{
		cmd: cmd, proxyPort: port,
		logFile: logFile, cfgPath: cfgPath,
	}

	// Wait for readiness
	if err := p.waitForReady(30 * time.Second); err != nil {
		p.cleanup()
		return nil, fmt.Errorf("tng failed to start: %w", err)
	}

	return p, nil
}

// ProxyPort returns the port the http_proxy is listening on.
func (p *Process) ProxyPort() int {
	return p.proxyPort
}

// LogPath returns the path to the TNG log file (for debugging).
func (p *Process) LogPath() string {
	if p.logFile != nil {
		return p.logFile.Name()
	}
	return ""
}

// waitForReady polls until TNG is accepting TCP connections on the proxy port.
func (p *Process) waitForReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	attempts := 0
	for time.Now().Before(deadline) {
		attempts++
		// Check if process exited prematurely
		if p.cmd.ProcessState != nil {
			return fmt.Errorf("process exited after %d attempts (log: %s)", attempts, p.LogPath())
		}
		if err := p.cmd.Process.Signal(syscall.Signal(0)); err != nil {
			return fmt.Errorf("process died after %d attempts: %w", attempts, err)
		}

		// Try TCP connection to the proxy port
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p.proxyPort), 500*time.Millisecond)
		if err == nil {
			conn.Close()
			// Extra buffer to avoid iptables/SO_MARK race conditions
			time.Sleep(200 * time.Millisecond)
			return nil
		}

		time.Sleep(200 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for tng on port %d after %d attempts", p.proxyPort, attempts)
}

// Close gracefully terminates the TNG subprocess and cleans up temp files.
func (p *Process) Close() error {
	return p.cleanup()
}

func (p *Process) cleanup() error {
	// Terminate subprocess gracefully, then force-kill if needed
	if p.cmd.Process != nil && p.cmd.ProcessState == nil {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- p.cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = p.cmd.Process.Kill()
			p.cmd.Wait()
		}
	}

	// Close log file
	if p.logFile != nil {
		p.logFile.Close()
	}

	// Remove temp config
	if p.cfgPath != "" {
		os.Remove(p.cfgPath)
	}

	return nil
}

// findFreePort allocates a random free TCP port on 127.0.0.1.
func findFreePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port, nil
}

// writeTempConfig writes the TNG config JSON to a temp file.
func writeTempConfig(port int, cfg *IngressConfig) (string, error) {
	configJSON, err := BuildIngressConfig(port, cfg)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "tng-cfg-*.json")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(configJSON); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	f.Close()
	return f.Name(), nil
}
