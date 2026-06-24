//go:build !integration

package tngproc

import (
	"encoding/json"
	"os"
	"testing"
)

func TestFindFreePort_ReturnsValidPort(t *testing.T) {
	port, err := findFreePort()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if port <= 0 || port > 65535 {
		t.Errorf("expected valid port number, got %d", port)
	}
}

func TestFindFreePort_DifferentPorts(t *testing.T) {
	port1, err1 := findFreePort()
	if err1 != nil {
		t.Fatalf("first call failed: %v", err1)
	}
	port2, err2 := findFreePort()
	if err2 != nil {
		t.Fatalf("second call failed: %v", err2)
	}
	if port1 == port2 {
		t.Errorf("expected different ports, got same: %d", port1)
	}
}

func TestWriteTempConfig_CreatesValidJson(t *testing.T) {
	cfg := &IngressConfig{NoRA: true}
	path, err := writeTempConfig(8080, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.Remove(path)

	// Verify file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("temp config file was not created")
	}

	// Read back and parse JSON
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read temp config: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON in temp config: %v", err)
	}

	addIngress, ok := result["add_ingress"].([]any)
	if !ok || len(addIngress) != 1 {
		t.Fatal("expected add_ingress array with one element")
	}

	ingress := addIngress[0].(map[string]any)
	if ingress["no_ra"] != true {
		t.Error("expected no_ra to be true")
	}
}
