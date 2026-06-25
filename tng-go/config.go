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
	// OHttp customizes OHTTP encryption settings (optional).
	// Mutually exclusive with RatsTls (not exposed on Config directly,
	// set via IngressConfig if needed).
	OHttp map[string]any `json:"ohttp,omitempty"`
	// Attest configures client-side attestation (optional).
	// Used when the client needs to provide attestation to the server.
	Attest map[string]any `json:"attest,omitempty"`
	// Verify configures server-side attestation verification (optional).
	// Used to validate the server's attestation token.
	Verify map[string]any `json:"verify,omitempty"`
	// NoRA disables remote attestation (debugging only, insecure).
	// Use only for local development.
	NoRA bool `json:"no_ra,omitempty"`
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
