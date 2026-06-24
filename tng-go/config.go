package tng

import "encoding/json"

// Config is the TNG client configuration.
// The field names and structure match the Rust serde format used by the
// WASM and Python SDKs.
//
// Example (verify-only):
//
//	cfg := &tng.Config{
//		Verify: map[string]any{
//			"model":       "background-check",
//			"as_provider": "coco",
//			"as_type":     "restful",
//			"as_addr":     "http://127.0.0.1:8080/",
//			"policy_ids":  []string{"default"},
//		},
//	}
//
// Example (mutual attestation):
//
//	cfg := &tng.Config{
//		Attest: map[string]any{
//			"model":       "background-check",
//			"aa_provider": "coco",
//			"aa_type":     "uds",
//			"aa_addr":     "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
//		},
//		Verify: map[string]any{
//			"model":       "background-check",
//			"as_provider": "coco",
//			"as_type":     "restful",
//			"as_addr":     "http://127.0.0.1:8080/",
//			"policy_ids":  []string{"default"},
//		},
//	}
type Config struct {
	OHttp  map[string]any `json:"ohttp,omitempty"`
	Attest map[string]any `json:"attest,omitempty"`
	Verify map[string]any `json:"verify,omitempty"`
	NoRA   bool           `json:"no_ra,omitempty"`
}

// FromJSON parses a JSON string into a Config.
func FromJSON(jsonStr string) (*Config, error) {
	var c Config
	if err := json.Unmarshal([]byte(jsonStr), &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// ToJSON serializes the Config to a JSON string for the Rust FFI.
func (c *Config) ToJSON() (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
