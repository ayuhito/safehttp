package safehttp_test

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"testing"

	safehttp "github.com/ayuhito/safehttp"
	"github.com/stretchr/testify/require"
)

func TestDefaultPolicy(t *testing.T) {
	guard, err := safehttp.NewGuard()
	require.NoError(t, err)

	require.NoError(t, guard.CheckURL(mustURL(t, "https://example.com/path")))

	tests := []struct {
		name string
		url  string
		err  error
	}{
		{name: "http scheme", url: "http://example.com", err: safehttp.ErrBlockedScheme},
		{name: "non-default port", url: "https://example.com:8443", err: safehttp.ErrBlockedPort},
		{name: "credentials", url: "https://user:pass@example.com", err: safehttp.ErrBlockedCredentials},
		{name: "loopback ipv4", url: "https://127.0.0.1", err: safehttp.ErrBlockedAddress},
		{name: "private ipv4", url: "https://10.0.0.1", err: safehttp.ErrBlockedAddress},
		{name: "metadata ipv4", url: "https://169.254.169.254", err: safehttp.ErrBlockedAddress},
		{name: "documentation ipv4", url: "https://198.51.100.1", err: safehttp.ErrBlockedAddress},
		{name: "multicast ipv4", url: "https://224.0.0.1", err: safehttp.ErrBlockedAddress},
		{name: "loopback ipv6", url: "https://[::1]", err: safehttp.ErrBlockedAddress},
		{name: "ula ipv6", url: "https://[fd00::1]", err: safehttp.ErrBlockedAddress},
		{name: "nat64 ipv6", url: "https://[64:ff9b::808:808]", err: safehttp.ErrBlockedAddress},
		{name: "discard-only ipv6", url: "https://[100::1]", err: safehttp.ErrBlockedAddress},
		{name: "link-local ipv6", url: "https://[fe80::1]", err: safehttp.ErrBlockedAddress},
		{name: "documentation ipv6", url: "https://[2001:db8::1]", err: safehttp.ErrBlockedAddress},
		{name: "sr-v6 sid ipv6", url: "https://[5f00::1]", err: safehttp.ErrBlockedAddress},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorIs(t, guard.CheckURL(mustURL(t, tc.url)), tc.err)
		})
	}

	req := &http.Request{Method: http.MethodGet, URL: mustURL(t, "https://example.com"), Host: "other.example.com"}
	require.ErrorIs(t, guard.CheckRequest(req), safehttp.ErrBlockedHostHeader)

	req = &http.Request{Method: http.MethodGet, URL: mustURL(t, "https://example.com"), Host: "example.com"}
	require.NoError(t, guard.CheckRequest(req))

	for _, host := range []string{
		"http://example.com",
		"example.com/path",
		"user@example.com",
		"example.com@127.0.0.1",
	} {
		req = &http.Request{Method: http.MethodGet, URL: mustURL(t, "https://example.com"), Host: host}
		require.ErrorIs(t, guard.CheckRequest(req), safehttp.ErrBlockedHostHeader, host)
	}
}

func TestHostPolicy(t *testing.T) {
	guard, err := safehttp.NewGuard(safehttp.AllowHosts("example.com", "*.example.net", "bücher.example"))
	require.NoError(t, err)

	allowed := []string{
		"https://example.com",
		"https://EXAMPLE.COM",
		"https://api.example.net",
		"https://api.EXAMPLE.net",
		"https://deep.api.example.net",
		"https://bücher.example",
		"https://xn--bcher-kva.example",
	}
	for _, rawURL := range allowed {
		require.NoError(t, guard.CheckURL(mustURL(t, rawURL)), rawURL)
	}

	blocked := []string{
		"https://example.net",
		"https://badexample.net",
		"https://other.example.com",
	}
	for _, rawURL := range blocked {
		require.ErrorIs(t, guard.CheckURL(mustURL(t, rawURL)), safehttp.ErrBlockedHost, rawURL)
	}
}

func TestInvalidHostPatterns(t *testing.T) {
	tests := []string{
		"",
		"*example.com",
		"api.*.example.com",
		"https://example.com",
		"example.com:443",
		"::1",
		"bad_host.example",
		"-example.com",
		"example-.com",
	}

	for _, pattern := range tests {
		t.Run(pattern, func(t *testing.T) {
			_, err := safehttp.NewGuard(safehttp.AllowHosts(pattern))
			require.Error(t, err)
		})
	}
}

func TestURLParsingAndPorts(t *testing.T) {
	guard, err := safehttp.NewGuard()
	require.NoError(t, err)

	_, err = safehttp.NewGuard(safehttp.AllowMethods("GET /"))
	require.Error(t, err)

	_, err = safehttp.NewGuard(safehttp.AllowSchemes("é"))
	require.Error(t, err)

	require.ErrorIs(t, guard.CheckURL(&url.URL{Scheme: "https"}), safehttp.ErrInvalidURL)

	require.ErrorIs(t, guard.CheckURL(&url.URL{Scheme: "https", Host: "example.com:bad"}), safehttp.ErrBlockedPort)
	require.ErrorIs(t, guard.CheckURL(&url.URL{Scheme: "https", Host: "example.com:"}), safehttp.ErrBlockedPort)
	require.ErrorIs(t, guard.CheckURL(&url.URL{Scheme: "https", Host: "bad_host.example"}), safehttp.ErrInvalidURL)
	require.ErrorIs(t, guard.CheckURL(&url.URL{Scheme: "https", Host: "0177.0.0.1"}), safehttp.ErrInvalidURL)
	require.ErrorIs(t, guard.CheckURL(&url.URL{Scheme: "https", Host: "2130706433"}), safehttp.ErrInvalidURL)
	require.ErrorIs(t, guard.CheckURL(&url.URL{Scheme: "https", Host: "999.999.999.999"}), safehttp.ErrInvalidURL)

	require.NoError(t, guard.CheckURL(mustURL(t, "https://[2606:4700:4700::1111]")))

	require.ErrorIs(t, guard.CheckURL(mustURL(t, "https://[::ffff:127.0.0.1]")), safehttp.ErrBlockedAddress)

	mappedAllow, err := safehttp.NewGuard(safehttp.AllowPrefixes(netip.MustParsePrefix("::ffff:127.0.0.1/128")))
	require.NoError(t, err)

	require.NoError(t, mappedAllow.CheckURL(mustURL(t, "https://[::ffff:127.0.0.1]")))

	mappedDeny, err := safehttp.NewGuard(safehttp.DenyPrefixes(netip.MustParsePrefix("::ffff:8.8.8.0/120")))
	require.NoError(t, err)

	require.ErrorIs(t, mappedDeny.CheckAddr("tcp4", netip.MustParseAddrPort("8.8.8.8:443")), safehttp.ErrBlockedAddress)

	denyWins, err := safehttp.NewGuard(
		safehttp.AllowCIDRs("8.8.8.0/24"),
		safehttp.DenyCIDRs("8.8.8.8/32"),
	)
	require.NoError(t, err)
	require.ErrorIs(t, denyWins.CheckAddr("tcp4", netip.MustParseAddrPort("8.8.8.8:443")), safehttp.ErrBlockedAddress)

	require.NoError(t, guard.CheckURL(mustURL(t, "https://example.com:443")))

	require.ErrorIs(t, guard.CheckURL(mustURL(t, "https://example.com:80")), safehttp.ErrBlockedPort)

	require.ErrorIs(t, guard.CheckURL(&url.URL{Scheme: "https", Host: "[2606:4700:4700::1111%eth0]"}), safehttp.ErrBlockedAddress)
	require.ErrorIs(t, guard.CheckAddr("tcp6", netip.MustParseAddrPort("[2606:4700:4700::1111%eth0]:443")), safehttp.ErrBlockedAddress)
	require.ErrorIs(t, guard.CheckAddr("tcp", netip.MustParseAddrPort("8.8.8.8:443")), safehttp.ErrBlockedNetwork)

	httpGuard, err := safehttp.NewGuard(safehttp.AllowSchemes("http", "https"), safehttp.AllowPorts(80, 443))
	require.NoError(t, err)

	require.NoError(t, httpGuard.CheckURL(mustURL(t, "http://example.com")))
}

func TestRedirectPolicy(t *testing.T) {
	guard, err := safehttp.NewGuard(safehttp.AllowHosts("example.com", "next.example.com"))
	require.NoError(t, err)

	require.NoError(t, guard.CheckRedirect(&http.Request{URL: mustURL(t, "https://next.example.com")}, []*http.Request{{URL: mustURL(t, "https://example.com")}}))

	defaultGuard, err := safehttp.NewGuard()
	require.NoError(t, err)

	err = defaultGuard.CheckRedirect(&http.Request{URL: mustURL(t, "https://127.0.0.1")}, []*http.Request{{URL: mustURL(t, "https://example.com")}})
	require.ErrorIs(t, err, safehttp.ErrBlockedRedirect)
	require.ErrorIs(t, err, safehttp.ErrBlockedAddress)

	noRedirects, err := safehttp.NewGuard(safehttp.NoRedirects())
	require.NoError(t, err)

	err = noRedirects.CheckRedirect(&http.Request{URL: mustURL(t, "https://example.com")}, []*http.Request{{URL: mustURL(t, "https://start.example.com")}})
	require.ErrorIs(t, err, safehttp.ErrBlockedRedirect)

	oneRedirect, err := safehttp.NewGuard(safehttp.MaxRedirects(1))
	require.NoError(t, err)

	err = oneRedirect.CheckRedirect(&http.Request{URL: mustURL(t, "https://example.com")}, []*http.Request{
		{URL: mustURL(t, "https://start.example.com")},
		{URL: mustURL(t, "https://middle.example.com")},
	})
	require.ErrorIs(t, err, safehttp.ErrBlockedRedirect)
}

func TestOptionsSnapshotSliceInputs(t *testing.T) {
	ports := []uint16{443}
	hosts := []string{"example.com"}
	prefixes := []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32")}

	opts := []safehttp.Option{
		safehttp.AllowPorts(ports...),
		safehttp.AllowHosts(hosts...),
		safehttp.DenyPrefixes(prefixes...),
	}

	ports[0] = 8443
	hosts[0] = "other.example.com"
	prefixes[0] = netip.MustParsePrefix("1.1.1.1/32")

	guard, err := safehttp.NewGuard(opts...)
	require.NoError(t, err)

	require.NoError(t, guard.CheckURL(mustURL(t, "https://example.com")))
	require.ErrorIs(t, guard.CheckAddr("tcp4", netip.MustParseAddrPort("8.8.8.8:443")), safehttp.ErrBlockedAddress)
}

func TestControlContext(t *testing.T) {
	guard, err := safehttp.NewGuard()
	require.NoError(t, err)

	require.NoError(t, guard.ControlContext(context.Background(), "tcp4", "8.8.8.8:443", nil))
	require.ErrorIs(t, guard.ControlContext(context.Background(), "tcp4", "127.0.0.1:443", nil), safehttp.ErrBlockedAddress)
	require.ErrorIs(t, guard.ControlContext(context.Background(), "tcp4", "not-addr", nil), safehttp.ErrInvalidURL)
}

func TestGuardConcurrentUse(t *testing.T) {
	guard, err := safehttp.NewGuard(safehttp.AllowHosts("example.com", "*.example.net"))
	require.NoError(t, err)

	u := mustURL(t, "https://api.example.net")

	var wg sync.WaitGroup

	errs := make(chan error, 200)

	for range 100 {
		wg.Go(func() {
			if err := guard.CheckURL(u); err != nil {
				errs <- err
			}

			if err := guard.CheckAddr("tcp4", netip.MustParseAddrPort("8.8.8.8:443")); err != nil {
				errs <- err
			}
		})
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
}
