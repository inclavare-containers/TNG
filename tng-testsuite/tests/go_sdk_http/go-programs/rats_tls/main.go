package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	tng "github.com/inclavare-containers/tng/tng-go"
)

func main() {
	// Use rats-TLS encryption instead of OHTTP
	cfg := &tng.Config{
		RatsTls: map[string]any{}, // default rats-TLS settings
		NoRA:    true,
	}
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("FAIL: read body: %v\n", err)
		os.Exit(1)
	}

	if !strings.Contains(string(body), "Hello World HTTP!") {
		fmt.Printf("FAIL: unexpected body: %s\n", string(body))
		os.Exit(1)
	}

	fmt.Println("PASS")
}
