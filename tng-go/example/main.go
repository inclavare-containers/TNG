package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"

	tng "github.com/inclavare-containers/tng/sdk-go/tng-go"
)

func main() {
	// Example: verify-only configuration
	cfg := &tng.Config{
		Verify: map[string]any{
			"model":       "background_check",
			"as_provider": "coco",
			"as_type":     "restful",
			"as_addr":     "http://127.0.0.1:8080/",
			"policy_ids":  []string{"default"},
		},
	}

	// Create the TNG RoundTripper
	rt, err := tng.NewRoundTripper(cfg)
	if err != nil {
		log.Fatalf("Failed to create RoundTripper: %v", err)
	}
	defer rt.Close()

	// Use with standard http.Client
	client := &http.Client{Transport: rt}

	resp, err := client.Get("http://target:30001/api/data")
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check server attestation
	info := tng.GetAttestationInfo(resp)
	if info != nil {
		fmt.Printf("Server attestation: token=%s\n", info.Token)
	}

	// Read body
	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	fmt.Printf("Status: %d, Body: %s\n", resp.StatusCode, string(buf[:n]))
}

// Example streaming: streaming works natively via http_proxy, no special option needed.
func exampleStreaming() {
	cfg := &tng.Config{
		Verify: map[string]any{
			"model":       "background_check",
			"as_provider": "coco",
			"as_type":     "restful",
			"as_addr":     "http://127.0.0.1:8080/",
			"policy_ids":  []string{"default"},
		},
	}

	rt, err := tng.NewRoundTripper(cfg)
	if err != nil {
		log.Fatalf("Failed to create RoundTripper: %v", err)
	}
	defer rt.Close()

	client := &http.Client{Transport: rt}
	resp, err := client.Get("http://target:30001/events")
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read streaming response line by line (e.g. SSE)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
}
