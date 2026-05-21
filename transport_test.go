package safehttp_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"

	safehttp "github.com/ayuhito/safehttp"
	"github.com/stretchr/testify/require"
)

func TestTransportSafety(t *testing.T) {
	_, err := safehttp.NewTransport(nil)
	require.NoError(t, err)

	base := http.DefaultTransport.(*http.Transport).Clone()
	base.MaxIdleConnsPerHost = 32

	_, err = safehttp.NewTransport(base)
	require.NoError(t, err)

	base = &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return nil, nil }}
	_, err = safehttp.NewTransport(base)
	require.ErrorIs(t, err, safehttp.ErrBlockedTransport)

	base = &http.Transport{
		DialTLS: func(string, string) (net.Conn, error) { return nil, nil },
	}
	_, err = safehttp.NewTransport(base)
	require.ErrorIs(t, err, safehttp.ErrBlockedTransport)

	base = &http.Transport{Dial: func(string, string) (net.Conn, error) { return nil, nil }}
	_, err = safehttp.NewTransport(base)
	require.ErrorIs(t, err, safehttp.ErrBlockedTransport)

	base = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	_, err = safehttp.NewTransport(base)
	require.ErrorIs(t, err, safehttp.ErrBlockedTransport)

	dialer := &net.Dialer{Timeout: time.Second}

	_, err = safehttp.NewTransport(&http.Transport{}, safehttp.Dialer(dialer))
	require.NoError(t, err)
	require.Nil(t, dialer.ControlContext)

	unsafeDialer := &net.Dialer{ControlContext: func(_ context.Context, _, _ string, _ syscall.RawConn) error { return nil }}
	_, err = safehttp.NewGuard(safehttp.Dialer(unsafeDialer))
	require.Error(t, err)
}

func TestClientAndExplicitOptions(t *testing.T) {
	client, err := safehttp.NewClient(safehttp.ClientTimeout(3 * time.Second))
	require.NoError(t, err)
	require.Equal(t, 3*time.Second, client.Timeout)

	guard, err := safehttp.NewGuard(safehttp.AllowCredentials(), safehttp.AllowCustomHostHeader())
	require.NoError(t, err)

	req := &http.Request{
		Method: http.MethodGet,
		URL:    mustURL(t, "https://user:pass@example.com"),
		Host:   "other.example.com",
	}
	require.NoError(t, guard.CheckRequest(req))
}

func TestMaxResponseHeaderBytes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Large", strings.Repeat("x", 2048))
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	client, err := safehttp.NewClient(localServerOptions(t, server.URL, safehttp.MaxResponseHeaderBytes(1))...)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		require.NoError(t, resp.Body.Close())
	}

	require.Error(t, err)
}

func TestClientBlocksResolvedLoopbackAddress(t *testing.T) {
	addrs, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", "localhost")
	require.NoError(t, err)

	hasLoopback := false
	for _, addr := range addrs {
		hasLoopback = hasLoopback || addr.IsLoopback()
	}

	if !hasLoopback {
		t.Skip("localhost does not resolve to loopback")
	}

	client, err := safehttp.NewClient(safehttp.AllowSchemes("http"), safehttp.AllowPorts(1))
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost:1", nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		require.NoError(t, resp.Body.Close())
	}

	require.Error(t, err)
	require.ErrorIs(t, err, safehttp.ErrBlockedAddress)
}
