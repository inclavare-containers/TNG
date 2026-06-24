package tng

import (
	"strings"
	"testing"
)

func TestConfigToJSON(t *testing.T) {
	cfg := &Config{
		Verify: map[string]any{
			"model":       "background-check",
			"as_provider": "coco",
			"as_type":     "restful",
			"as_addr":     "http://127.0.0.1:8080/",
			"policy_ids":  []string{"default"},
		},
	}

	jsonStr, err := cfg.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	if !strings.Contains(jsonStr, `"verify"`) {
		t.Errorf("JSON missing 'verify' key")
	}
	if !strings.Contains(jsonStr, `"background-check"`) {
		t.Errorf("JSON missing 'background-check' model")
	}
	if !strings.Contains(jsonStr, `"coco"`) {
		t.Errorf("JSON missing 'coco' provider")
	}
}

func TestConfigToJSONWithAttest(t *testing.T) {
	cfg := &Config{
		Attest: map[string]any{
			"model":       "background-check",
			"aa_provider": "coco",
			"aa_type":     "uds",
			"aa_addr":     "unix:///run/attestation-agent.sock",
		},
		Verify: map[string]any{
			"model":       "background-check",
			"as_provider": "coco",
			"as_type":     "restful",
			"as_addr":     "http://127.0.0.1:8080/",
			"policy_ids":  []string{"default"},
		},
	}

	jsonStr, err := cfg.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	if !strings.Contains(jsonStr, `"attest"`) {
		t.Errorf("JSON missing 'attest' key")
	}
	if !strings.Contains(jsonStr, `"verify"`) {
		t.Errorf("JSON missing 'verify' key")
	}
}

func TestFromJSON(t *testing.T) {
	jsonStr := `{"verify":{"model":"passport","as_provider":"ita","ita_jwks_addr":"http://example.com/jwks","policy_ids":["default"]}}`
	cfg, err := FromJSON(jsonStr)
	if err != nil {
		t.Fatalf("FromJSON failed: %v", err)
	}
	if cfg.Verify == nil {
		t.Fatal("Verify config is nil")
	}
}

func TestNilConfig(t *testing.T) {
	_, err := NewRoundTripper(nil)
	if err != ErrNilConfig {
		t.Fatalf("expected ErrNilConfig, got %v", err)
	}
}
