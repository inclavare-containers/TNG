package tngproc

import (
	"encoding/json"
	"fmt"
)

// IngressConfig holds the TNG client-side ingress configuration.
type IngressConfig struct {
	// OHTTP config map (passed through to TNG). If nil and RatsTls is nil,
	// defaults to empty OHTTP config (self-generated keys).
	OHttp map[string]any `json:"ohttp,omitempty"`
	// RatsTLS config map (mutually exclusive with OHttp).
	RatsTls map[string]any `json:"rats_tls,omitempty"`
	// NoRA disables remote attestation (for local development).
	NoRA bool `json:"no_ra,omitempty"`
	// Verify config for server attestation verification.
	Verify map[string]any `json:"verify,omitempty"`
	// Attest config for client attestation.
	Attest map[string]any `json:"attest,omitempty"`
}

// BuildIngressConfig creates the TNG JSON config for an http_proxy ingress.
// The config is written to a temp file and passed via --config-file.
//
// This mirrors _build_tng_config() in the Python SDK (tng-python/tng/_tng.py).
func BuildIngressConfig(proxyPort int, cfg *IngressConfig) ([]byte, error) {
	// OHttp and RatsTls are mutually exclusive
	if cfg.OHttp != nil && cfg.RatsTls != nil {
		return nil, fmt.Errorf("OHttp and RatsTls are mutually exclusive")
	}

	ingress := map[string]any{
		"http_proxy": map[string]any{
			"proxy_listen": map[string]any{
				"host": "127.0.0.1",
				"port": proxyPort,
			},
		},
	}

	// OHTTP / RatsTLS — default to OHTTP if neither specified
	if cfg.OHttp != nil {
		ingress["ohttp"] = cfg.OHttp
	} else if cfg.RatsTls == nil {
		ingress["ohttp"] = map[string]any{}
	}
	if cfg.RatsTls != nil {
		ingress["rats_tls"] = cfg.RatsTls
	}

	// Optional fields
	if cfg.NoRA {
		ingress["no_ra"] = true
	}
	if cfg.Verify != nil {
		ingress["verify"] = cfg.Verify
	}
	if cfg.Attest != nil {
		ingress["attest"] = cfg.Attest
	}

	config := map[string]any{
		"add_ingress": []any{ingress},
	}

	return json.Marshal(config)
}
