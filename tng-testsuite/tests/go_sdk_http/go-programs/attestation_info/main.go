package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	tng "github.com/inclavare-containers/tng/sdk-go/tng-go"
)

func main() {
	cfg := &tng.Config{NoRA: true}
	rt, err := tng.NewRoundTripper(cfg)
	if err != nil {
		fmt.Printf("FAIL: NewRoundTripper: %v\n", err)
		os.Exit(1)
	}
	defer rt.Close()

	client := &http.Client{Transport: rt, Timeout: 30 * time.Second}
	resp, err := client.Get("http://192.168.1.1:20001/api/data")
	if err != nil {
		fmt.Printf("FAIL: GET request: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("FAIL: expected status 200, got %d\n", resp.StatusCode)
		os.Exit(1)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		fmt.Println("FAIL: expected Content-Type header to be accessible")
		os.Exit(1)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("FAIL: read body: %v\n", err)
		os.Exit(1)
	}
	if !strings.Contains(string(body), "Hello World HTTP!") {
		fmt.Printf("FAIL: unexpected body: %s\n", string(body))
		os.Exit(1)
	}

	// Call GetAttestationInfo — should not panic in NoRA mode
	// In NoRA mode, no attestation header is added, so info should be nil
	info := tng.GetAttestationInfo(resp)
	if info != nil {
		fmt.Printf("FAIL: expected nil attestation info in NoRA mode, got token=%s, as_provider=%s\n", info.Token, info.ASProvider)
		os.Exit(1)
	}

	fmt.Println("PASS (attestation info is nil, as expected in NoRA mode)")
}
