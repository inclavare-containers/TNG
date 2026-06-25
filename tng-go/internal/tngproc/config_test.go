//go:build !integration

package tngproc

import (
	"encoding/json"
	"testing"
)

func TestBuildIngressConfig_NoRA(t *testing.T) {
	cfg := &IngressConfig{NoRA: true}
	data, err := BuildIngressConfig(8080, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	addIngress, ok := result["add_ingress"].([]any)
	if !ok || len(addIngress) != 1 {
		t.Fatalf("expected add_ingress array with one element")
	}

	ingress := addIngress[0].(map[string]any)
	httpProxy, ok := ingress["http_proxy"].(map[string]any)
	if !ok {
		t.Fatal("expected http_proxy field")
	}

	proxyListen := httpProxy["proxy_listen"].(map[string]any)
	if proxyListen["host"] != "127.0.0.1" {
		t.Errorf("expected host 127.0.0.1, got %v", proxyListen["host"])
	}
	if int(proxyListen["port"].(float64)) != 8080 {
		t.Errorf("expected port 8080, got %v", proxyListen["port"])
	}

	if ingress["no_ra"] != true {
		t.Errorf("expected no_ra to be true")
	}

	// Default OHTTP should be present when neither OHttp nor RatsTls is set
	if _, ok := ingress["ohttp"]; !ok {
		t.Error("expected default ohttp field")
	}
}

func TestBuildIngressConfig_VerifyMode(t *testing.T) {
	verifyCfg := map[string]any{"cas": []string{"ca.pem"}}
	cfg := &IngressConfig{Verify: verifyCfg}
	data, err := BuildIngressConfig(9090, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	addIngress := result["add_ingress"].([]any)
	ingress := addIngress[0].(map[string]any)

	verifyField, ok := ingress["verify"].(map[string]any)
	if !ok {
		t.Fatal("expected verify field")
	}

	cas := verifyField["cas"].([]any)
	if len(cas) != 1 || cas[0].(string) != "ca.pem" {
		t.Errorf("expected verify.cas to contain ca.pem")
	}
}

func TestBuildIngressConfig_AttestAndVerify(t *testing.T) {
	attestCfg := map[string]any{"policy": "default"}
	verifyCfg := map[string]any{"cas": []string{"ca.pem"}}
	cfg := &IngressConfig{Attest: attestCfg, Verify: verifyCfg}
	data, err := BuildIngressConfig(7070, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	addIngress := result["add_ingress"].([]any)
	ingress := addIngress[0].(map[string]any)

	if _, ok := ingress["attest"]; !ok {
		t.Error("expected attest field")
	}
	if _, ok := ingress["verify"]; !ok {
		t.Error("expected verify field")
	}
}

func TestBuildIngressConfig_OHttpCustom(t *testing.T) {
	ohttpCfg := map[string]any{"config": "custom-ohttp"}
	cfg := &IngressConfig{OHttp: ohttpCfg}
	data, err := BuildIngressConfig(6060, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	addIngress := result["add_ingress"].([]any)
	ingress := addIngress[0].(map[string]any)

	ohttp := ingress["ohttp"].(map[string]any)
	if ohttp["config"] != "custom-ohttp" {
		t.Errorf("expected custom ohttp config")
	}

	// RatsTLS should not be present
	if _, ok := ingress["rats_tls"]; ok {
		t.Error("did not expect rats_tls when ohttp is set")
	}
}

func TestBuildIngressConfig_RatsTls(t *testing.T) {
	ratsTlsCfg := map[string]any{"cert": "server.crt", "key": "server.key"}
	cfg := &IngressConfig{RatsTls: ratsTlsCfg}
	data, err := BuildIngressConfig(5050, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	addIngress := result["add_ingress"].([]any)
	ingress := addIngress[0].(map[string]any)

	ratsTls := ingress["rats_tls"].(map[string]any)
	if ratsTls["cert"] != "server.crt" {
		t.Errorf("expected cert server.crt")
	}
	if ratsTls["key"] != "server.key" {
		t.Errorf("expected key server.key")
	}

	// Default OHTTP should NOT be added when RatsTls is set
	if _, ok := ingress["ohttp"]; ok {
		t.Error("did not expect ohttp when rats_tls is set")
	}
}

func TestBuildIngressConfig_OHttpAndRatsTlsMutualExclusivity(t *testing.T) {
	cfg := &IngressConfig{
		OHttp:   map[string]any{"key": "test"},
		RatsTls: map[string]any{"cert": "test.crt"},
	}
	_, err := BuildIngressConfig(8080, cfg)
	if err == nil {
		t.Fatal("expected error when both OHttp and RatsTls are set")
	}
	if err.Error() != "OHttp and RatsTls are mutually exclusive" {
		t.Errorf("unexpected error message: %v", err)
	}
}
