package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
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

	// Read response incrementally to verify streaming works through the tunnel
	scanner := bufio.NewScanner(resp.Body)
	lineCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 0 {
			lineCount++
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("FAIL: scanner error: %v\n", err)
		os.Exit(1)
	}

	if lineCount == 0 {
		fmt.Println("FAIL: no data received through tunnel")
		os.Exit(1)
	}

	fmt.Printf("PASS (received %d lines through streaming tunnel)\n", lineCount)
}
