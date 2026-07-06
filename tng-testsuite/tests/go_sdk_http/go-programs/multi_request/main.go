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
	cfg := &tng.Config{NoRA: true}
	rt, err := tng.NewRoundTripper(cfg)
	if err != nil {
		fmt.Printf("FAIL: NewRoundTripper: %v\n", err)
		os.Exit(1)
	}
	defer rt.Close()

	client := &http.Client{Transport: rt, Timeout: 30 * time.Second}

	// Make 5 sequential GET requests through the same RoundTripper
	for i := 1; i <= 5; i++ {
		resp, err := client.Get("http://192.168.1.1:20001/api/data")
		if err != nil {
			fmt.Printf("FAIL: request %d: %v\n", i, err)
			os.Exit(1)
		}

		if resp.StatusCode != http.StatusOK {
			fmt.Printf("FAIL: request %d: expected status 200, got %d\n", i, resp.StatusCode)
			resp.Body.Close()
			os.Exit(1)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			fmt.Printf("FAIL: request %d: read body: %v\n", i, err)
			os.Exit(1)
		}

		if !strings.Contains(string(body), "Hello World HTTP!") {
			fmt.Printf("FAIL: request %d: unexpected body: %s\n", i, string(body))
			os.Exit(1)
		}
	}

	fmt.Println("PASS (5 sequential requests succeeded)")
}
