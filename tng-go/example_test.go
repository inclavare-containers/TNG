package tng

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
)

func Example_basicUsage() {
	cfg := &Config{
		NoRA: true,
	}

	rt, err := NewRoundTripper(cfg)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer func() { _ = rt.Close() }()

	client := &http.Client{Transport: rt}
	_ = client

	fmt.Println("RoundTripper created")
	// Output: RoundTripper created
}

func Example_fallbackPassthrough() {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "fallback response")
	}))
	defer ts.Close()

	cfg := &Config{
		NoRA: true,
	}

	rt, err := NewRoundTripper(cfg, WithFallback(http.DefaultTransport, func(u *url.URL) bool {
		return u.Host != "target:30001"
	}))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer func() { _ = rt.Close() }()

	client := &http.Client{Transport: rt}
	resp, err := client.Get(ts.URL)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	fmt.Println("fallback status:", resp.StatusCode)
	// Output: fallback status: 200
}

func Example_errorHandling() {
	cfg := &Config{
		NoRA: true,
	}

	rt, err := NewRoundTripper(cfg)
	if err != nil {
		var tngErr *Error
		if errors.As(err, &tngErr) {
			fmt.Printf("operation: %s, message: %s\n", tngErr.Op, tngErr.Msg)
		}
		return
	}
	defer func() { _ = rt.Close() }()

	fmt.Println("RoundTripper created")
	// Output: RoundTripper created
}

func Example_noRaTesting() {
	cfg := &Config{
		NoRA: true,
	}

	rt, err := NewRoundTripper(cfg)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer func() { _ = rt.Close() }()

	fmt.Println("no-RA RoundTripper created")
	// Output: no-RA RoundTripper created
}

func Example_fromJSON() {
	cfg, err := FromJSON(`{"no_ra": true}`)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	rt, err := NewRoundTripper(cfg)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer func() { _ = rt.Close() }()

	fmt.Println("parsed config and created RoundTripper")
	// Output: parsed config and created RoundTripper
}
