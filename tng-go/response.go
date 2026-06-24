package tng

import (
	"context"
	"encoding/json"
	"net/http"
)

// contextKey is the context key for storing attestation info.
type contextKey struct{}

// AttestationInfo contains the attestation result from the server.
// This is the Go equivalent of the `attest_info` property on WASM responses.
type AttestationInfo struct {
	// Token is the serialized attestation token (JWT or similar).
	Token string `json:"token"`
	// ASProvider is the attestation service provider ("coco" or "ita").
	ASProvider string `json:"as_provider,omitempty"`
	// ASAddr is the attestation service address.
	ASAddr string `json:"as_addr,omitempty"`
	// PolicyIDs are the policy IDs used for verification.
	PolicyIDs []string `json:"policy_ids,omitempty"`
}

func withAttestationInfo(ctx context.Context, info *AttestationInfo) context.Context {
	return context.WithValue(ctx, contextKey{}, info)
}

// GetAttestationInfo retrieves attestation info from an http.Response returned
// by TngRoundTripper.
func GetAttestationInfo(resp *http.Response) *AttestationInfo {
	if resp == nil || resp.Request == nil {
		return nil
	}
	info, _ := resp.Request.Context().Value(contextKey{}).(*AttestationInfo)
	return info
}

// ParseAttestationInfoFromHeaders extracts attestation info from
// HTTP response headers (TNG returns it as a JSON header).
func ParseAttestationInfoFromHeaders(headers http.Header) (*AttestationInfo, error) {
	jsonStr := headers.Get("X-Tng-Attestation-Info")
	if jsonStr == "" {
		return nil, nil
	}
	return ParseAttestationInfo(jsonStr)
}

// ParseAttestationInfo parses the raw attestation info JSON from the FFI.
func ParseAttestationInfo(jsonStr string) (*AttestationInfo, error) {
	if jsonStr == "" {
		return nil, nil
	}
	var info AttestationInfo
	if err := json.Unmarshal([]byte(jsonStr), &info); err != nil {
		return nil, err
	}
	return &info, nil
}
