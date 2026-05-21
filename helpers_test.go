package safehttp_test

import (
	"net/url"
	"strconv"
	"testing"

	safehttp "github.com/ayuhito/safehttp"
	"github.com/stretchr/testify/require"
)

func mustURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()

	u, err := url.Parse(rawURL)
	require.NoError(t, err, rawURL)

	return u
}

func localServerOptions(t testing.TB, rawURL string, opts ...safehttp.Option) []safehttp.Option {
	t.Helper()

	u, err := url.Parse(rawURL)
	require.NoError(t, err)

	port, err := strconv.ParseUint(u.Port(), 10, 16)
	require.NoError(t, err)

	options := []safehttp.Option{
		safehttp.AllowSchemes("http"),
		safehttp.AllowPorts(uint16(port)),
		safehttp.AllowCIDRs("127.0.0.0/8", "::1/128"),
	}

	return append(options, opts...)
}

func mustBenchmarkURL(b *testing.B, rawURL string) *url.URL {
	b.Helper()

	u, err := url.Parse(rawURL)
	if err != nil {
		b.Fatalf("parse url %q: %v", rawURL, err)
	}

	return u
}
