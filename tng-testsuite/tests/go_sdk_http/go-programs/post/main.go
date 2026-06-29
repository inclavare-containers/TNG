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

	body := strings.NewReader(`{"test":"payload"}`)
	req, err := http.NewRequest(http.MethodPost, "http://192.168.1.1:20001/echo", body)
	if err != nil {
		fmt.Printf("FAIL: create request: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Transport: rt, Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("FAIL: POST request: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("FAIL: expected status 200, got %d\n", resp.StatusCode)
		os.Exit(1)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("FAIL: read body: %v\n", err)
		os.Exit(1)
	}

	if !strings.Contains(string(respBody), "payload") {
		fmt.Printf("FAIL: expected echo of payload, got: %s\n", string(respBody))
		os.Exit(1)
	}

	fmt.Println("PASS")
}
