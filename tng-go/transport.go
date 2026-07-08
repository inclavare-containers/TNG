package tng

import (
	"net/http"
	"net/url"
)

// Transport implements http.RoundTripper by forwarding requests
// to a local TNG http_proxy instance.
//
// TNG is used as a standard forward HTTP proxy: the client emits the request
// with the absolute target URI in the request line
// (e.g. `POST http://target/path HTTP/1.1`) and the Host header set to the
// target host. TNG reads that absolute URI to determine the backend
// destination and applies OHTTP (or rats-TLS) encryption transparently.
//
// Forwarding is delegated to net/http's built-in proxy support via
// http.Transport.Proxy, which emits exactly that absolute-URI request form —
// the same form curl uses when given `all_proxy`. This preserves the request
// path/query and reuses a single underlying *http.Transport so connections
// are pooled.
type Transport struct {
	proxyURL *url.URL
	// fallback transport for non-TNG URLs (optional). When set together with
	// match, requests for which match(url) returns true bypass TNG and use
	// fallback instead.
	fallback http.RoundTripper
	match    func(*url.URL) bool
	// base carries the actual proxying. Its Proxy field returns proxyURL so
	// net/http emits absolute-URI request lines to the local TNG ingress.
	base *http.Transport
}

// NewTransport creates a Transport that forwards requests to the
// TNG http_proxy at the given URL.
func NewTransport(proxyURL *url.URL) *Transport {
	t := &Transport{
		proxyURL: proxyURL,
		fallback: http.DefaultTransport,
	}
	// Start from a clone of DefaultTransport (sensible timeouts, TLS config)
	// and only override the proxy selector.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyURL(proxyURL)
	t.base = tr
	return t
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
	// Bypass TNG for URLs the caller opted out of.
	if t.match != nil && t.match(req.URL) {
		return t.fallback.RoundTrip(req)
	}
	// Otherwise let net/http forward to the TNG http_proxy with an
	// absolute-URI request line (path/query preserved).
	return t.base.RoundTrip(req)
}

// Close releases idle connections held by the underlying transport. It is
// safe to call multiple times.
func (t *Transport) Close() {
	if t.base != nil {
		t.base.CloseIdleConnections()
	}
}

// ProxyURL returns the proxy URL this transport forwards to.
func (t *Transport) ProxyURL() *url.URL {
	return t.proxyURL
}
