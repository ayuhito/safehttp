package safehttp

import (
	"net/netip"
	"slices"
)

var (
	// Most special IPv6 addresses are outside 2000::/3.
	//
	// By default, IPv6 destinations must be globally routed unless a caller
	// explicitly allows a narrower prefix.
	//
	// Source: https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space.xhtml
	ipv6GlobalUnicast = netip.MustParsePrefix("2000::/3")

	// These are special-purpose ranges that are not fully covered by the simple
	// netip predicates below. They include documentation, benchmarking,
	// carrier-grade NAT, transition, reserved, and other non-public ranges that
	// are blocked for user-controlled URLs by default.
	//
	// Sources:
	//   - https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
	//   - https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
	specialDenyV4, specialDenyV6 = splitPrefixes([]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.31.196.0/24"),
		netip.MustParsePrefix("192.52.193.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("192.175.48.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),

		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:2::/48"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("2620:4f:8000::/48"),
		netip.MustParsePrefix("3fff::/20"),
	})
)

// splitPrefixes canonicalizes address policy prefixes once during construction.
func splitPrefixes(prefixes []netip.Prefix) ([]netip.Prefix, []netip.Prefix) {
	if len(prefixes) == 0 {
		return []netip.Prefix{}, []netip.Prefix{}
	}

	v4 := make([]netip.Prefix, 0, len(prefixes))
	v6 := make([]netip.Prefix, 0, len(prefixes))

	for _, prefix := range prefixes {
		prefix = prefix.Masked()

		// IPv4-mapped IPv6 addresses use ::ffff:0:0/96. If the prefix is narrow
		// enough to describe only IPv4 bits, store it as IPv4 so it matches the
		// Addr.Unmap call in CheckAddr.
		const v4InV6PrefixBits = 96

		if prefix.Addr().Is4In6() && prefix.Bits() >= v4InV6PrefixBits {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-v4InV6PrefixBits)
		}

		if prefix.Addr().Is4() {
			v4 = append(v4, prefix)
			continue
		}

		v6 = append(v6, prefix)
	}

	slices.SortFunc(v4, netip.Prefix.Compare)
	slices.SortFunc(v6, netip.Prefix.Compare)

	return v4, v6
}

// containsPrefix reports the first matching policy prefix for an IP address.
func containsPrefix(v4 []netip.Prefix, v6 []netip.Prefix, ip netip.Addr) (netip.Prefix, bool) {
	prefixes := v6
	if ip.Is4() {
		prefixes = v4
	}

	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return prefix, true
		}
	}

	return netip.Prefix{}, false
}
