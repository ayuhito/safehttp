package safehttp

import (
	"fmt"
	"net"
	"net/http"
	"time"
)

// NewClient builds an HTTP client with a guarded transport and redirect policy.
func NewClient(opts ...Option) (*http.Client, error) {
	guard, err := NewGuard(opts...)
	if err != nil {
		return nil, err
	}

	transport, err := cloneTransport(nil, guard)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport:     &roundTripper{guard: guard, next: transport},
		CheckRedirect: guard.CheckRedirect,
		Timeout:       guard.clientTimeout,
	}, nil
}

// NewTransport clones base, installs guarded dialing, and returns a safe round tripper.
func NewTransport(base *http.Transport, opts ...Option) (http.RoundTripper, error) {
	guard, err := NewGuard(opts...)
	if err != nil {
		return nil, err
	}

	transport, err := cloneTransport(base, guard)
	if err != nil {
		return nil, err
	}

	return &roundTripper{
		guard: guard,
		next:  transport,
	}, nil
}

func cloneTransport(base *http.Transport, guard *Guard) (*http.Transport, error) {
	switch {
	case base == nil:
		base = http.DefaultTransport.(*http.Transport)
	case base.TLSClientConfig != nil && base.TLSClientConfig.InsecureSkipVerify:
		// safehttp's default client uses Go's normal certificate verification.
		// A base transport must not silently weaken that HTTPS boundary.
		return nil, fmt.Errorf("%w: base transport disables tls certificate verification", ErrBlockedTransport)
	default:
		// TLS dial hooks bypass DialContext entirely, so a cloned base transport
		// must not inherit them.
		//
		// Source: https://pkg.go.dev/net/http#Transport
		//nolint:staticcheck // Deprecated TLS dial hooks still bypass DialContext when set.
		if base.DialTLS != nil || base.DialTLSContext != nil {
			return nil, fmt.Errorf("%w: base transport has a TLS dial hook that would bypass safehttp", ErrBlockedTransport)
		}

		//nolint:staticcheck // Deprecated Dial is still rejected when set.
		if base.Dial != nil {
			return nil, fmt.Errorf("%w: base transport has a custom dial; pass safehttp.Dialer instead", ErrBlockedTransport)
		}
	}

	transport := base.Clone()

	dialer := guard.dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	} else {
		copied := *dialer
		dialer = &copied
	}

	// safehttp owns dialing even when a base transport is supplied. This keeps
	// the post-DNS address check on the path to every connection.
	dialer.Control = nil
	dialer.ControlContext = guard.ControlContext

	transport.DialContext = dialer.DialContext
	transport.DialTLSContext = nil

	// Proxies move final DNS resolution and reachability decisions to the proxy.
	// Keep them disabled unless this package grows an explicit proxy option.
	transport.Proxy = nil

	if guard.maxResponseHeader > 0 {
		transport.MaxResponseHeaderBytes = guard.maxResponseHeader
	}

	return transport, nil
}

// roundTripper keeps request and response checks outside http.Transport.
//
// http.Transport still owns connection pooling, TLS, HTTP/2, and proxy-disabled
// dialing. This wrapper only validates the request before the transport runs and
// wraps the response body when a response size limit is configured.
type roundTripper struct {
	guard *Guard
	next  http.RoundTripper
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := rt.guard.CheckRequest(req); err != nil {
		return nil, err
	}

	resp, err := rt.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if rt.guard.maxResponseBytes > 0 && resp.Body != nil {
		resp.Body = http.MaxBytesReader(nil, resp.Body, rt.guard.maxResponseBytes)
	}

	return resp, nil
}

func (rt *roundTripper) CloseIdleConnections() {
	if closer, ok := rt.next.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

var _ http.RoundTripper = (*roundTripper)(nil)
