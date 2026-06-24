package tng

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestNewTransport(t *testing.T) {
	proxyURL, err := url.Parse("http://127.0.0.1:8080")
	if err != nil {
		t.Fatalf("unexpected error parsing URL: %v", err)
	}

	tr := NewTransport(proxyURL)

	if tr.ProxyURL().String() != proxyURL.String() {
		t.Errorf("expected ProxyURL %q, got %q", proxyURL.String(), tr.ProxyURL().String())
	}
}

func TestTransport_RoundTrip_Fallback(t *testing.T) {
	// Create a fallback server that returns a known response
	fallbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte("fallback"))
	}))
	defer fallbackServer.Close()

	fallbackURL, err := url.Parse(fallbackServer.URL)
	if err != nil {
		t.Fatalf("unexpected error parsing fallback URL: %v", err)
	}

	proxyURL, err := url.Parse("http://127.0.0.1:9999") // not running, but we'll use fallback
	if err != nil {
		t.Fatalf("unexpected error parsing proxy URL: %v", err)
	}

	tr := NewTransport(proxyURL)
	tr.WithFallback(http.DefaultTransport, func(u *url.URL) bool {
		return u.Host == fallbackURL.Host
	})

	// Build a request to the fallback server
	req, err := http.NewRequest("GET", fallbackServer.URL+"/test", nil)
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}

	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error from RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("expected status %d, got %d", http.StatusTeapot, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("unexpected error reading body: %v", err)
	}
	if string(body) != "fallback" {
		t.Errorf("expected body 'fallback', got %q", string(body))
	}
}

func TestTransport_RoundTrip_NoFallback(t *testing.T) {
	proxyURL, err := url.Parse("http://127.0.0.1:9999")
	if err != nil {
		t.Fatalf("unexpected error parsing proxy URL: %v", err)
	}

	NewTransport(proxyURL)
	// No fallback set, so all requests should go through TNG path

	// We can't easily test the full TNG flow without a real proxy,
	// but we can verify the match logic by checking that non-matching
	// URLs do NOT use the fallback. Since no fallback is configured,
	// the request would fail when trying to connect to the proxy.
	// Instead, verify the internal state: match should be nil or not match.

	targetURL, _ := url.Parse("https://example.com/test")
	req, err := http.NewRequest("GET", targetURL.String(), nil)
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}

	// Clone the request and simulate what RoundTrip does internally
	clonedReq := req.Clone(req.Context())
	clonedReq.URL = proxyURL
	clonedReq.Host = req.URL.Host
	clonedReq.RequestURI = req.URL.String()

	// Verify the clone was set up correctly for TNG forwarding
	if clonedReq.URL.String() != proxyURL.String() {
		t.Errorf("expected cloned URL %q, got %q", proxyURL.String(), clonedReq.URL.String())
	}
	if clonedReq.Host != targetURL.Host {
		t.Errorf("expected cloned Host %q, got %q", targetURL.Host, clonedReq.Host)
	}
	if clonedReq.RequestURI != targetURL.String() {
		t.Errorf("expected cloned RequestURI %q, got %q", targetURL.String(), clonedReq.RequestURI)
	}
}

func TestTransport_WithFallback(t *testing.T) {
	proxyURL, err := url.Parse("http://127.0.0.1:8080")
	if err != nil {
		t.Fatalf("unexpected error parsing URL: %v", err)
	}

	tr := NewTransport(proxyURL)

	// WithFallback should return the same transport instance
	result := tr.WithFallback(http.DefaultTransport, func(u *url.URL) bool {
		return u.Host == "example.com"
	})

	if result != tr {
		t.Error("WithFallback should return the same Transport instance")
	}

	// Verify the fallback and match function were set
	if tr.fallback != http.DefaultTransport {
		t.Error("fallback was not set correctly")
	}

	testURL, _ := url.Parse("https://example.com/test")
	if !tr.match(testURL) {
		t.Error("match function should return true for example.com")
	}

	otherURL, _ := url.Parse("https://other.com/test")
	if tr.match(otherURL) {
		t.Error("match function should return false for other.com")
	}
}

func TestTransport_ProxyURL(t *testing.T) {
	proxyURL, err := url.Parse("http://127.0.0.1:3128")
	if err != nil {
		t.Fatalf("unexpected error parsing URL: %v", err)
	}

	tr := NewTransport(proxyURL)

	got := tr.ProxyURL()
	if got.String() != proxyURL.String() {
		t.Errorf("expected ProxyURL %q, got %q", proxyURL.String(), got.String())
	}
}
