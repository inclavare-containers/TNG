package tng

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestParseAttestationInfoFromHeaders(t *testing.T) {
	t.Run("with valid header containing JSON", func(t *testing.T) {
		info := &AttestationInfo{
			Token:     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test",
			ASProvider: "coco",
			ASAddr:    "http://localhost:8080",
			PolicyIDs: []string{"policy-1", "policy-2"},
		}
		jsonBytes, err := json.Marshal(info)
		if err != nil {
			t.Fatalf("failed to marshal info: %v", err)
		}

		headers := http.Header{}
		headers.Set("X-Tng-Attestation-Info", string(jsonBytes))

		result, err := ParseAttestationInfoFromHeaders(headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Token != info.Token {
			t.Errorf("token: got %q, want %q", result.Token, info.Token)
		}
		if result.ASProvider != info.ASProvider {
			t.Errorf("as_provider: got %q, want %q", result.ASProvider, info.ASProvider)
		}
		if result.ASAddr != info.ASAddr {
			t.Errorf("as_addr: got %q, want %q", result.ASAddr, info.ASAddr)
		}
		if len(result.PolicyIDs) != len(info.PolicyIDs) {
			t.Errorf("policy_ids length: got %d, want %d", len(result.PolicyIDs), len(info.PolicyIDs))
		}
		for i, id := range info.PolicyIDs {
			if result.PolicyIDs[i] != id {
				t.Errorf("policy_ids[%d]: got %q, want %q", i, result.PolicyIDs[i], id)
			}
		}
	})

	t.Run("with empty header", func(t *testing.T) {
		headers := http.Header{}

		result, err := ParseAttestationInfoFromHeaders(headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("expected nil result, got %+v", result)
		}
	})

	t.Run("with malformed JSON in header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("X-Tng-Attestation-Info", "{invalid json}")

		result, err := ParseAttestationInfoFromHeaders(headers)
		if err == nil {
			t.Fatal("expected error for malformed JSON, got nil")
		}
		if result != nil {
			t.Errorf("expected nil result on error, got %+v", result)
		}
	})
}

func TestParseAttestationInfo_PartialJSON(t *testing.T) {
	t.Run("with partial JSON containing only token field", func(t *testing.T) {
		jsonStr := `{"token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.partial"}`

		result, err := ParseAttestationInfo(jsonStr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Token != "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.partial" {
			t.Errorf("token: got %q, want %q", result.Token, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.partial")
		}
		if result.ASProvider != "" {
			t.Errorf("as_provider should be empty, got %q", result.ASProvider)
		}
		if result.ASAddr != "" {
			t.Errorf("as_addr should be empty, got %q", result.ASAddr)
		}
		if len(result.PolicyIDs) != 0 {
			t.Errorf("policy_ids should be empty, got %v", result.PolicyIDs)
		}
	})

	t.Run("with empty policy_ids array", func(t *testing.T) {
		jsonStr := `{"token":"test-token","policy_ids":[]}`

		result, err := ParseAttestationInfo(jsonStr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Token != "test-token" {
			t.Errorf("token: got %q, want %q", result.Token, "test-token")
		}
		if result.PolicyIDs == nil {
			t.Error("policy_ids should not be nil for empty array")
		}
		if len(result.PolicyIDs) != 0 {
			t.Errorf("policy_ids should be empty, got %v", result.PolicyIDs)
		}
	})

	t.Run("with empty string", func(t *testing.T) {
		result, err := ParseAttestationInfo("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("expected nil result for empty string, got %+v", result)
		}
	})
}

func TestGetAttestationInfo_NilCases(t *testing.T) {
	t.Run("with nil response", func(t *testing.T) {
		result := GetAttestationInfo(nil)
		if result != nil {
			t.Errorf("expected nil result for nil response, got %+v", result)
		}
	})

	t.Run("with response but nil request", func(t *testing.T) {
		resp := &http.Response{}

		result := GetAttestationInfo(resp)
		if result != nil {
			t.Errorf("expected nil result for response with nil request, got %+v", result)
		}
	})
}
