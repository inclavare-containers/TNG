package tng

import (
	"encoding/json"
	"errors"
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

func TestFromJSONWithCommentsAndTrailingCommas(t *testing.T) {
	jsonStr := `
		// line comment
		{
			/* block comment */
			"no_ra": true,
		}
	`
	cfg, err := FromJSON(jsonStr)
	if err != nil {
		t.Fatalf("FromJSON failed: %v", err)
	}
	if !cfg.NoRA {
		t.Fatal("NoRA should be true")
	}
}

func TestFromJSONKeepsCommentMarkersInsideStrings(t *testing.T) {
	const addr = "http://example.com/*not-a-comment*/"
	cfg, err := FromJSON(`{"verify":{"as_addr":"http://example.com/*not-a-comment*/"}}`)
	if err != nil {
		t.Fatalf("FromJSON failed: %v", err)
	}
	if got := cfg.Verify["as_addr"]; got != addr {
		t.Fatalf("as_addr = %v, want %s", got, addr)
	}
}

func TestFromJSONWithLeadingBOM(t *testing.T) {
	cfg, err := FromJSON("\ufeff" + `{"no_ra": true}`)
	if err != nil {
		t.Fatalf("FromJSON failed: %v", err)
	}
	if !cfg.NoRA {
		t.Fatal("NoRA should be true")
	}
}

func TestFromJSONWithLeadingBOMAndComments(t *testing.T) {
	cfg, err := FromJSON("\ufeff// comment\n{\"no_ra\": true,}")
	if err != nil {
		t.Fatalf("FromJSON failed: %v", err)
	}
	if !cfg.NoRA {
		t.Fatal("NoRA should be true")
	}
}

func TestFromJSONRejectsBOMInsideDocument(t *testing.T) {
	if _, err := FromJSON("{}\ufeff"); err == nil {
		t.Fatal("U+FEFF inside the document should be rejected")
	}
}

func TestFromJSONStillRejectsJSON5Extensions(t *testing.T) {
	if _, err := FromJSON(`{no_ra: true}`); err == nil {
		t.Fatal("unquoted property names should be rejected")
	}
	if _, err := FromJSON(`{"no_ra": 'true'}`); err == nil {
		t.Fatal("single-quoted strings should be rejected")
	}
}

func TestFromJSONPreservesErrorOffset(t *testing.T) {
	const base = `{"no_ra": true "verify": {}}`
	const comment = "// comment\n"

	_, plainErr := FromJSON(base)
	_, commentedErr := FromJSON(comment + base)

	var plainSyntax, commentedSyntax *json.SyntaxError
	if !errors.As(plainErr, &plainSyntax) {
		t.Fatalf("expected *json.SyntaxError, got %v", plainErr)
	}
	if !errors.As(commentedErr, &commentedSyntax) {
		t.Fatalf("expected *json.SyntaxError, got %v", commentedErr)
	}
	want := plainSyntax.Offset + int64(len(comment))
	if commentedSyntax.Offset != want {
		t.Fatalf("offset = %d, want %d", commentedSyntax.Offset, want)
	}
}
