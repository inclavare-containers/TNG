package tng

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"

	"github.com/inclavare-containers/tng/sdk-go/tng-go/internal/tngproc"
)

// TngRoundTripper implements http.RoundTripper.
//
// It spawns a local TNG subprocess as an http_proxy, encrypts requests
// via OHTTP (or rats-TLS), and decrypts responses.
//
// Usage:
//
//	rt, _ := tng.NewRoundTripper(cfg)
//	defer rt.Close()
//	client := &http.Client{Transport: rt}
//	resp, _ := client.Get("http://target:30001/api/data")
type TngRoundTripper struct {
	proc      *tngproc.Process
	transport *Transport
	closed    atomic.Bool
}

// RoundTripperOption is a functional option for NewRoundTripper.
type RoundTripperOption func(*roundTripperOpts)

type roundTripperOpts struct {
	fallback  fallback
	logFilter string
}

type fallback struct {
	rt    http.RoundTripper
	match func(*url.URL) bool
}

// WithFallback sets a fallback RoundTripper for URLs matching the predicate.
// When match(url) returns true, the request is delegated to the fallback
// transport instead of going through TNG OHTTP encryption.
func WithFallback(rt http.RoundTripper, match func(*url.URL) bool) RoundTripperOption {
	return func(o *roundTripperOpts) {
		o.fallback.rt = rt
		o.fallback.match = match
	}
}

// WithLogFilter enables TNG internal logging.
func WithLogFilter(filter string) RoundTripperOption {
	return func(o *roundTripperOpts) {
		o.logFilter = filter
	}
}

// NewRoundTripper creates a new TNG RoundTripper.
//
// It finds the TNG binary, spawns a subprocess with an http_proxy ingress,
// and returns a RoundTripper that forwards all requests through it.
func NewRoundTripper(cfg *Config, opts ...RoundTripperOption) (*TngRoundTripper, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}

	opt := roundTripperOpts{}
	for _, fn := range opts {
		fn(&opt)
	}

	// Build subprocess config
	ingressCfg := &tngproc.IngressConfig{
		OHttp:   cfg.OHttp,
		RatsTls: cfg.RatsTls,
		NoRA:    cfg.NoRA,
		Verify:  cfg.Verify,
		Attest:  cfg.Attest,
	}

	proc, err := tngproc.New(ingressCfg)
	if err != nil {
		return nil, &Error{Op: "NewRoundTripper", Err: err}
	}

	// Create transport pointing to the local proxy
	proxyURL := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort("127.0.0.1", fmt.Sprint(proc.ProxyPort())),
	}
	transport := NewTransport(proxyURL)

	// Apply fallback if configured
	if opt.fallback.rt != nil && opt.fallback.match != nil {
		transport.WithFallback(opt.fallback.rt, opt.fallback.match)
	}

	return &TngRoundTripper{
		proc:      proc,
		transport: transport,
	}, nil
}

// RoundTrip implements http.RoundTripper.
func (t *TngRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.closed.Load() {
		return nil, ErrClosedTransport
	}

	// Read request body into a buffer (http_proxy expects rewritable body)
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, &Error{Op: "RoundTrip", Msg: "failed to read body", Err: err}
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
	}

	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		return nil, &Error{Op: "RoundTrip", Err: err}
	}

	// Parse attestation info from response headers if present
	if info, err := ParseAttestationInfoFromHeaders(resp.Header); err == nil && info != nil {
		req = req.WithContext(withAttestationInfo(req.Context(), info))
		resp.Request = req
	} else if err != nil {
		log.Printf("tng: failed to parse attestation info: %v", err)
	}

	return resp, nil
}

// Close terminates the TNG subprocess and cleans up resources.
func (t *TngRoundTripper) Close() error {
	if t.closed.Swap(true) {
		return nil
	}
	return t.proc.Close()
}
