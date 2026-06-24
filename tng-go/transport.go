package tng

import (
	"net/http"
	"net/url"
)

// Transport implements http.RoundTripper by forwarding requests
// to a local TNG http_proxy instance.
//
// The TNG proxy reads the Host header to determine the backend
// destination and applies OHTTP (or rats-TLS) encryption transparently.
type Transport struct {
	proxyURL *url.URL
	// fallback transport for non-TNG URLs (optional)
	fallback http.RoundTripper
	// match function: return true to use fallback for this URL
	match func(*url.URL) bool
}

// NewTransport creates a Transport that forwards requests to the
// TNG http_proxy at the given URL.
func NewTransport(proxyURL *url.URL) *Transport {
	return &Transport{
		proxyURL: proxyURL,
		fallback: http.DefaultTransport,
	}
}

// WithFallback sets a fallback transport for URLs matching the predicate.
// When match(url) returns true, the request bypasses TNG and uses the
// fallback transport directly.
func (t *Transport) WithFallback(rt http.RoundTripper, match func(*url.URL) bool) *Transport {
	t.fallback = rt
	t.match = match
	return t
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Check if this URL should bypass TNG
	if t.match != nil && t.match(req.URL) {
		return t.fallback.RoundTrip(req)
	}

	// Forward to TNG http_proxy.
	//
	// The http_proxy ingress expects standard HTTP requests:
	// - The RequestURI field carries the full target URL
	// - The Host header determines the backend destination
	// - TNG handles OHTTP encryption transparently
	proxyReq := req.Clone(req.Context())
	proxyReq.URL = t.proxyURL
	proxyReq.Host = req.URL.Host
	proxyReq.RequestURI = req.URL.String()

	// Use the default transport to send the request to the local proxy
	return http.DefaultTransport.(*http.Transport).Clone().RoundTrip(proxyReq)
}

// ProxyURL returns the proxy URL this transport forwards to.
func (t *Transport) ProxyURL() *url.URL {
	return t.proxyURL
}
