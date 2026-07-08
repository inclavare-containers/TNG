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
		_, _ = w.Write([]byte("fallback"))
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
	defer func() { _ = resp.Body.Close() }()

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
	// Regression guard for the path-loss bug: a hand-rolled clone that set
	// `proxyReq.URL = t.proxyURL` made net/http emit `POST /` (the proxy
	// URL's path) as the request line, dropping the target path. The TNG
	// ingress then derived the OHTTP key URL from `/` and forwarded `/` to
	// the backend, 404'ing on backends that serve keys/content at a real path
	// (e.g. PAI-EAS /api/predict/<svc>).
	//
	// We stand up a fake forward proxy and assert the request line carries the
	// full absolute target URI (path + query preserved) and the Host header
	// is the target host.
	var gotRequestURI, gotHost string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestURI = r.RequestURI
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("unexpected error parsing proxy URL: %v", err)
	}

	tr := NewTransport(proxyURL)
	// No fallback set, so the request must go through the proxy.

	// Use a non-resolvable target host: the proxy receives the absolute URI
	// and does not connect onward, so no DNS is required.
	req, err := http.NewRequest(http.MethodPost,
		"http://target.example.com/api/predict/svc/v1/completions?foo=bar", nil)
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}

	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error from RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	wantURI := "http://target.example.com/api/predict/svc/v1/completions?foo=bar"
	if gotRequestURI != wantURI {
		t.Errorf("request line target URI = %q, want %q (path/query must be preserved)",
			gotRequestURI, wantURI)
	}
	if gotHost != "target.example.com" {
		t.Errorf("Host header = %q, want target.example.com", gotHost)
	}

	// Closing must not panic and must release idle connections.
	tr.Close()
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
