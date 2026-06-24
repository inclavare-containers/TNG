package tng

import (
	"net/http"
	"testing"
)

func TestParseAttestationInfo(t *testing.T) {
	// Valid JSON
	info, err := ParseAttestationInfo(`{"token":"abc123","as_provider":"coco","as_addr":"http://127.0.0.1:8080/","policy_ids":["default"]}`)
	if err != nil {
		t.Fatalf("ParseAttestationInfo failed: %v", err)
	}
	if info.Token != "abc123" {
		t.Errorf("expected token 'abc123', got %q", info.Token)
	}
	if info.ASProvider != "coco" {
		t.Errorf("expected provider 'coco', got %q", info.ASProvider)
	}

	// Empty string
	info, err = ParseAttestationInfo("")
	if err != nil {
		t.Fatalf("ParseAttestationInfo(\"\") failed: %v", err)
	}
	if info != nil {
		t.Error("expected nil info for empty string")
	}

	// Malformed JSON
	info, err = ParseAttestationInfo(`{invalid json}`)
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestGetAttestationInfo(t *testing.T) {
	// Nil response
	if GetAttestationInfo(nil) != nil {
		t.Error("GetAttestationInfo(nil) should return nil")
	}

	// Response with no attestation info
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	resp := &http.Response{StatusCode: 200, Request: req}
	if GetAttestationInfo(resp) != nil {
		t.Error("GetAttestationInfo should return nil when no info attached")
	}

	// Response with attestation info attached
	info := &AttestationInfo{Token: "test-token", ASProvider: "coco"}
	req2, _ := http.NewRequest("GET", "http://example.com", nil)
	req2 = req2.WithContext(withAttestationInfo(req2.Context(), info))
	resp2 := &http.Response{StatusCode: 200, Request: req2}
	got := GetAttestationInfo(resp2)
	if got == nil {
		t.Fatal("expected attestation info but got nil")
	}
	if got.Token != "test-token" {
		t.Errorf("expected token 'test-token', got %q", got.Token)
	}
}
