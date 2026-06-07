package safehttp_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	safehttp "github.com/ayuhito/safehttp"
	"github.com/stretchr/testify/require"
)

func TestOriginPolicy(t *testing.T) {
	guard, err := safehttp.NewGuard(safehttp.AllowOrigins(
		"https://example.com/base/path?ignored=true#fragment",
		"http://api.example.com:8080",
		"https://bücher.example",
		"https://[2606:4700:4700::1111]",
		"custom+scheme://service.example:9000/path",
	))
	require.NoError(t, err)

	allowed := []string{
		"https://example.com",
		"HTTPS://example.com",
		"https://example.com:443/other/path?query=true#fragment",
		"https://EXAMPLE.COM",
		"http://api.example.com:8080/v1",
		"https://xn--bcher-kva.example",
		"https://bücher.example",
		"https://[2606:4700:4700::1111]/dns-query",
		"custom+scheme://service.example:9000/path",
	}
	for _, rawURL := range allowed {
		require.NoError(t, guard.CheckURL(mustURL(t, rawURL)), rawURL)
	}

	blocked := []string{
		"http://example.com",
		"https://example.com:444",
		"https://api.example.com",
		"http://api.example.com",
		"https://service.example:9000",
	}
	for _, rawURL := range blocked {
		require.ErrorIs(t, guard.CheckURL(mustURL(t, rawURL)), safehttp.ErrBlockedOrigin, rawURL)
	}
}

func TestOriginPolicyDoesNotCrossProduct(t *testing.T) {
	guard, err := safehttp.NewGuard(safehttp.AllowOrigins(
		"https://a.example",
		"http://b.example:8080",
	))
	require.NoError(t, err)

	require.NoError(t, guard.CheckURL(mustURL(t, "https://a.example")))
	require.NoError(t, guard.CheckURL(mustURL(t, "http://b.example:8080")))

	blocked := []string{
		"https://b.example",
		"http://a.example:8080",
		"https://a.example:8080",
		"http://b.example",
	}
	for _, rawURL := range blocked {
		require.ErrorIs(t, guard.CheckURL(mustURL(t, rawURL)), safehttp.ErrBlockedOrigin, rawURL)
	}
}

func TestInvalidOrigins(t *testing.T) {
	_, err := safehttp.NewGuard(safehttp.AllowOrigins())
	require.Error(t, err)

	tests := []string{
		"",
		"/relative",
		"example.com",
		"https://",
		"https://user:pass@example.com",
		"https://example.com:bad",
		"https://[::1",
		"https://*.example.com",
		"https://bad_host.example",
		"https://-example.com",
		"https://example-.com",
		"https://0177.0.0.1",
		"custom+scheme://service.example",
	}

	for _, rawOrigin := range tests {
		t.Run(rawOrigin, func(t *testing.T) {
			_, err := safehttp.NewGuard(safehttp.AllowOrigins(rawOrigin))
			require.Error(t, err)
		})
	}
}

func TestOriginOptionComposition(t *testing.T) {
	conflicts := []struct {
		name string
		opts []safehttp.Option
	}{
		{
			name: "origins then schemes",
			opts: []safehttp.Option{safehttp.AllowOrigins("https://example.com"), safehttp.AllowSchemes("https")},
		},
		{
			name: "schemes then origins",
			opts: []safehttp.Option{safehttp.AllowSchemes("https"), safehttp.AllowOrigins("https://example.com")},
		},
		{
			name: "origins then ports",
			opts: []safehttp.Option{safehttp.AllowOrigins("https://example.com"), safehttp.AllowPorts(443)},
		},
		{
			name: "ports then origins",
			opts: []safehttp.Option{safehttp.AllowPorts(443), safehttp.AllowOrigins("https://example.com")},
		},
		{
			name: "origins then hosts",
			opts: []safehttp.Option{safehttp.AllowOrigins("https://example.com"), safehttp.AllowHosts("example.com")},
		},
		{
			name: "hosts then origins",
			opts: []safehttp.Option{safehttp.AllowHosts("example.com"), safehttp.AllowOrigins("https://example.com")},
		},
	}

	for _, tc := range conflicts {
		t.Run(tc.name, func(t *testing.T) {
			_, err := safehttp.NewGuard(tc.opts...)
			require.Error(t, err)
		})
	}

	guard, err := safehttp.NewGuard(
		safehttp.AllowOrigins("https://example.com"),
		safehttp.AllowMethods(http.MethodGet),
		safehttp.AllowCredentials(),
		safehttp.MaxRedirects(1),
		safehttp.MaxResponseHeaderBytes(1),
		safehttp.MaxResponseBytes(1),
		safehttp.AllowCIDRs("127.0.0.0/8"),
	)
	require.NoError(t, err)

	require.NoError(t, guard.CheckRequest(&http.Request{
		Method: http.MethodGet,
		URL:    mustURL(t, "https://user:pass@example.com/path"),
	}))

	err = guard.CheckRequest(&http.Request{
		Method: http.MethodPost,
		URL:    mustURL(t, "https://example.com/path"),
	})
	require.ErrorIs(t, err, safehttp.ErrBlockedMethod)

	require.NoError(t, guard.CheckAddr("tcp4", netip.MustParseAddrPort("127.0.0.1:443")))
}

func TestRepeatedAllowOriginsReplacesOriginList(t *testing.T) {
	guard, err := safehttp.NewGuard(
		safehttp.AllowOrigins("https://first.example"),
		safehttp.AllowOrigins("https://second.example"),
	)
	require.NoError(t, err)

	require.ErrorIs(t, guard.CheckURL(mustURL(t, "https://first.example")), safehttp.ErrBlockedOrigin)
	require.NoError(t, guard.CheckURL(mustURL(t, "https://second.example")))
}

func TestOriginPolicyKeepsLoopbackAddressPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	guard, err := safehttp.NewGuard(safehttp.AllowOrigins(server.URL))
	require.NoError(t, err)
	require.ErrorIs(t, guard.CheckURL(mustURL(t, server.URL)), safehttp.ErrBlockedAddress)

	loopbackGuard, err := safehttp.NewGuard(
		safehttp.AllowOrigins(server.URL),
		safehttp.AllowCIDRs("127.0.0.0/8", "::1/128"),
	)
	require.NoError(t, err)
	require.NoError(t, loopbackGuard.CheckURL(mustURL(t, server.URL)))
}

func TestOriginRedirectPolicy(t *testing.T) {
	guard, err := safehttp.NewGuard(safehttp.AllowOrigins("https://example.com"))
	require.NoError(t, err)

	err = guard.CheckRedirect(
		&http.Request{URL: mustURL(t, "https://example.com/after")},
		[]*http.Request{{URL: mustURL(t, "https://example.com/before")}},
	)
	require.NoError(t, err)

	err = guard.CheckRedirect(
		&http.Request{URL: mustURL(t, "https://other.example/after")},
		[]*http.Request{{URL: mustURL(t, "https://example.com/before")}},
	)
	require.ErrorIs(t, err, safehttp.ErrBlockedRedirect)
	require.ErrorIs(t, err, safehttp.ErrBlockedOrigin)
}
