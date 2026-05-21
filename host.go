package safehttp

import (
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// dnsLookup converts DNS names into the ASCII form used for comparisons.
//
// Sources:
//   - https://pkg.go.dev/golang.org/x/net/idna
//   - https://www.unicode.org/reports/tr46/
var dnsLookup = idna.New(
	idna.MapForLookup(),
	idna.VerifyDNSLength(true),
	idna.BidiRule(),
)

// hostMatcher stores the optional host allowlist in normalized ASCII form.
//
// A zero-value matcher allows every host. When configured, exact entries match
// one host and wildcard entries only match real subdomains, so "*.example.com"
// matches "api.example.com" but not "example.com" or "badexample.com".
type hostMatcher struct {
	exactHosts       map[string]struct{}
	wildcardSuffixes []string
}

// compileHostMatcher validates host patterns once during construction.
//
// Only exact hosts and leading wildcard patterns are accepted. Broad patterns
// like "*example.com" are rejected because they are ambiguous and can allow
// suffix-confusion domains.
func compileHostMatcher(patterns []string) (hostMatcher, error) {
	if len(patterns) == 0 {
		return hostMatcher{}, nil
	}

	matcher := hostMatcher{
		exactHosts: make(map[string]struct{}, len(patterns)),
	}

	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if after, ok := strings.CutPrefix(pattern, "*."); ok {
			host, err := normalizeHostPattern(after)
			if err != nil {
				return hostMatcher{}, fmt.Errorf("safehttp: invalid wildcard host %q: %w", pattern, err)
			}

			// Store wildcard patterns as ".example.com" so a suffix check can
			// require a label boundary and avoid matching "badexample.com".
			matcher.wildcardSuffixes = append(matcher.wildcardSuffixes, "."+host)

			continue
		}

		if strings.Contains(pattern, "*") {
			return hostMatcher{}, fmt.Errorf("safehttp: invalid host %q: wildcard must be a leading *", pattern)
		}

		host, err := normalizeHostPattern(pattern)
		if err != nil {
			return hostMatcher{}, fmt.Errorf("safehttp: invalid host %q: %w", pattern, err)
		}

		matcher.exactHosts[host] = struct{}{}
	}

	return matcher, nil
}

func (m hostMatcher) allows(host string) bool {
	if len(m.exactHosts) == 0 && len(m.wildcardSuffixes) == 0 {
		return true
	}

	if _, ok := m.exactHosts[host]; ok {
		return true
	}

	for _, suffix := range m.wildcardSuffixes {
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			return true
		}
	}

	return false
}

func normalizeURLHost(host string) (string, netip.Addr, error) {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if host == "" {
		return "", netip.Addr{}, fmt.Errorf("host cannot be empty")
	}

	// Numeric-looking hosts are treated as IP literals and must parse
	// canonically; this avoids octal, dword, and other ambiguous IPv4 forms.
	addr, isLiteral, err := parseIPLiteralHost(host)
	if err != nil {
		return "", netip.Addr{}, err
	}

	if isLiteral {
		addr = addr.Unmap()
		return addr.String(), addr, nil
	}

	// DNS comparison is done on IDNA ASCII form so Unicode and punycode inputs
	// share one canonical representation for host allowlists and errors.
	normalized, err := dnsLookup.ToASCII(host)

	return normalized, netip.Addr{}, err
}

func parseIPLiteralHost(host string) (netip.Addr, bool, error) {
	if !strings.ContainsAny(host, ":%") && strings.Trim(host, "0123456789.") != "" {
		return netip.Addr{}, false, nil
	}

	// IPv6-looking hosts and numeric IPv4-looking hosts must parse
	// canonically. This rejects scoped syntax, octal IPv4, dword IPv4, and
	// other ambiguous forms instead of letting them fall through to DNS.
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, true, fmt.Errorf("ip literal is invalid")
	}

	return addr, true, nil
}

// normalizeHostPattern accepts host allowlist entries, not URLs.
//
// Ports and IPv6 literals are rejected in AllowHosts because port policy lives
// in AllowPorts and IPv6 literals contain colons that are ambiguous in patterns.
func normalizeHostPattern(host string) (string, error) {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if host == "" {
		return "", fmt.Errorf("host cannot be empty")
	}

	if strings.Contains(host, "://") || strings.ContainsAny(host, "/@") {
		return "", fmt.Errorf("host must not include url syntax")
	}

	if strings.Contains(host, ":") {
		return "", fmt.Errorf("host must not include ports or ipv6 literals")
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String(), nil
	}

	return dnsLookup.ToASCII(host)
}
