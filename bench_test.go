package safehttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"

	safehttp "github.com/ayuhito/safehttp"
)

func BenchmarkCheckURLExactHost(b *testing.B) {
	guard, err := safehttp.NewGuard(safehttp.AllowHosts("example.com"))
	if err != nil {
		b.Fatal(err)
	}

	u := mustBenchmarkURL(b, "https://example.com")

	for b.Loop() {
		if err := guard.CheckURL(u); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCheckURLWildcardHost(b *testing.B) {
	guard, err := safehttp.NewGuard(safehttp.AllowHosts("*.example.com"))
	if err != nil {
		b.Fatal(err)
	}

	u := mustBenchmarkURL(b, "https://api.example.com")

	for b.Loop() {
		if err := guard.CheckURL(u); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCheckAddrPublicIPv4(b *testing.B) {
	guard, err := safehttp.NewGuard()
	if err != nil {
		b.Fatal(err)
	}

	addr := netip.MustParseAddrPort("8.8.8.8:443")

	for b.Loop() {
		if err := guard.CheckAddr("tcp4", addr); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCheckAddrPublicIPv6(b *testing.B) {
	guard, err := safehttp.NewGuard()
	if err != nil {
		b.Fatal(err)
	}

	addr := netip.MustParseAddrPort("[2606:4700:4700::1111]:443")
	for b.Loop() {
		if err := guard.CheckAddr("tcp6", addr); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCheckAddrBlockedIPv4(b *testing.B) {
	guard, err := safehttp.NewGuard()
	if err != nil {
		b.Fatal(err)
	}

	addr := netip.MustParseAddrPort("127.0.0.1:443")

	for b.Loop() {
		if err := guard.CheckAddr("tcp4", addr); err == nil {
			b.Fatal("expected blocked address")
		}
	}
}

func BenchmarkCheckAddrManyCustomPrefixes(b *testing.B) {
	prefixes := make([]netip.Prefix, 0, 256)
	for i := range 256 {
		prefixes = append(prefixes, netip.MustParsePrefix("8."+strconv.Itoa(i)+".0.0/16"))
	}

	guard, err := safehttp.NewGuard(safehttp.DenyPrefixes(prefixes...))
	if err != nil {
		b.Fatal(err)
	}

	addr := netip.MustParseAddrPort("9.9.9.9:443")

	for b.Loop() {
		if err := guard.CheckAddr("tcp4", addr); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoundTripLocalSafeClient(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	u := mustBenchmarkURL(b, server.URL)

	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil {
		b.Fatal(err)
	}

	client, err := safehttp.NewClient(
		safehttp.AllowSchemes("http"),
		safehttp.AllowPorts(uint16(port)),
		safehttp.AllowCIDRs("127.0.0.0/8"),
	)
	if err != nil {
		b.Fatal(err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		resp, err := client.Do(req.Clone(context.Background()))
		if err != nil {
			b.Fatal(err)
		}

		resp.Body.Close()
	}
}

func BenchmarkRoundTripLocalPlainClient(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := server.Client()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		resp, err := client.Do(req.Clone(context.Background()))
		if err != nil {
			b.Fatal(err)
		}

		resp.Body.Close()
	}
}
