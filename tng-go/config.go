package tng

import (
	"bytes"
	"encoding/json"

	"github.com/tidwall/jsonc"
)

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
	// Mutually exclusive with RatsTls.
	OHttp map[string]any `json:"ohttp,omitempty"`
	// RatsTls customizes rats-TLS encryption settings (optional).
	// Mutually exclusive with OHttp.
	// When set, the TNG subprocess uses rats-TLS instead of OHTTP for
	// transport encryption. Requires the server egress to also be
	// configured with rats_tls.
	RatsTls map[string]any `json:"rats_tls,omitempty"`
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

// FromJSON parses a JSON string into a Config. The TNG CLI accepts comments,
// trailing commas, and a leading UTF-8 BOM, so this helper does too. Other
// JSON5 extensions are still rejected by encoding/json.
func FromJSON(jsonStr string) (*Config, error) {
	var c Config
	b := []byte(jsonStr)
	if bytes.HasPrefix(b, []byte("\xef\xbb\xbf")) {
		// Replace the BOM with spaces rather than trimming it so byte offsets
		// in encoding/json errors still line up with the original text.
		copy(b, "   ")
	}
	if err := json.Unmarshal(jsonc.ToJSON(b), &c); err != nil {
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
