package safehttp

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Option changes safehttp construction.
type Option func(*options) error

type options struct {
	schemes           []string
	ports             []uint16
	hosts             []string
	methods           []string
	maxRedirects      int
	allowCredentials  bool
	allowCustomHost   bool
	allowPrefixes     []netip.Prefix
	denyPrefixes      []netip.Prefix
	dialer            *net.Dialer
	clientTimeout     time.Duration
	maxResponseHeader int64
	maxResponseBytes  int64
}

// AllowSchemes replaces the default allowed URL schemes.
func AllowSchemes(schemes ...string) Option {
	schemes = slices.Clone(schemes)

	return func(o *options) error {
		if len(schemes) == 0 {
			return fmt.Errorf("safehttp: allowed schemes cannot be empty")
		}

		o.schemes = schemes

		return nil
	}
}

// AllowPorts replaces the default allowed destination ports.
func AllowPorts(ports ...uint16) Option {
	ports = slices.Clone(ports)

	return func(o *options) error {
		if len(ports) == 0 {
			return fmt.Errorf("safehttp: allowed ports cannot be empty")
		}

		if slices.Contains(ports, 0) {
			return fmt.Errorf("safehttp: allowed port cannot be 0")
		}

		o.ports = ports

		return nil
	}
}

// AllowHosts restricts requests to exact hosts or leading wildcard patterns.
func AllowHosts(hosts ...string) Option {
	hosts = slices.Clone(hosts)

	return func(o *options) error {
		if len(hosts) == 0 {
			return fmt.Errorf("safehttp: allowed hosts cannot be empty")
		}

		o.hosts = hosts

		return nil
	}
}

// AllowMethods restricts requests to the provided HTTP methods.
func AllowMethods(methods ...string) Option {
	methods = slices.Clone(methods)

	return func(o *options) error {
		if len(methods) == 0 {
			return fmt.Errorf("safehttp: allowed methods cannot be empty")
		}

		o.methods = methods

		return nil
	}
}

// MaxRedirects sets how many redirects a client may follow.
func MaxRedirects(n int) Option {
	return func(o *options) error {
		if n < 0 {
			return fmt.Errorf("safehttp: max redirects cannot be negative")
		}

		o.maxRedirects = n

		return nil
	}
}

// NoRedirects blocks every redirect.
func NoRedirects() Option {
	return MaxRedirects(0)
}

// AllowCredentials permits URL userinfo.
func AllowCredentials() Option {
	return func(o *options) error {
		o.allowCredentials = true
		return nil
	}
}

// AllowCustomHostHeader permits a Request.Host value that differs from the URL.
func AllowCustomHostHeader() Option {
	return func(o *options) error {
		o.allowCustomHost = true
		return nil
	}
}

// AllowPrefixes permits destination IP prefixes that the default policy blocks.
//
// Use it for tests, private infrastructure, or other non-public destinations.
// DenyPrefixes still wins when the same address is covered by both an allow
// rule and a deny rule.
func AllowPrefixes(prefixes ...netip.Prefix) Option {
	prefixes = slices.Clone(prefixes)

	return func(o *options) error {
		if len(prefixes) == 0 {
			return fmt.Errorf("safehttp: allow prefixes cannot be empty")
		}

		for _, prefix := range prefixes {
			if !prefix.IsValid() {
				return fmt.Errorf("safehttp: invalid allow prefix")
			}
		}

		o.allowPrefixes = append(o.allowPrefixes, prefixes...)

		return nil
	}
}

// DenyPrefixes blocks additional destination IP prefixes.
//
// Deny rules are checked before allow rules. Use them to make the default
// public-destination policy stricter for an application.
func DenyPrefixes(prefixes ...netip.Prefix) Option {
	prefixes = slices.Clone(prefixes)

	return func(o *options) error {
		if len(prefixes) == 0 {
			return fmt.Errorf("safehttp: deny prefixes cannot be empty")
		}

		for _, prefix := range prefixes {
			if !prefix.IsValid() {
				return fmt.Errorf("safehttp: invalid deny prefix")
			}
		}

		o.denyPrefixes = append(o.denyPrefixes, prefixes...)

		return nil
	}
}

// AllowCIDRs parses and permits destination CIDR ranges.
//
// This is the string form of AllowPrefixes for callers that load policy from
// text or environment-specific configuration.
func AllowCIDRs(cidrs ...string) Option {
	cidrs = slices.Clone(cidrs)

	return func(o *options) error {
		if len(cidrs) == 0 {
			return fmt.Errorf("safehttp: allow cidrs cannot be empty")
		}

		for _, cidr := range cidrs {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
			if err != nil {
				return fmt.Errorf("safehttp: invalid allow cidr %q: %w", cidr, err)
			}

			o.allowPrefixes = append(o.allowPrefixes, prefix)
		}

		return nil
	}
}

// DenyCIDRs parses and blocks additional destination CIDR ranges.
//
// This is the string form of DenyPrefixes for callers that load policy from
// text or environment-specific configuration.
func DenyCIDRs(cidrs ...string) Option {
	cidrs = slices.Clone(cidrs)

	return func(o *options) error {
		if len(cidrs) == 0 {
			return fmt.Errorf("safehttp: deny cidrs cannot be empty")
		}

		for _, cidr := range cidrs {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
			if err != nil {
				return fmt.Errorf("safehttp: invalid deny cidr %q: %w", cidr, err)
			}

			o.denyPrefixes = append(o.denyPrefixes, prefix)
		}

		return nil
	}
}

// Dialer uses a copy of dialer and installs safehttp's control hook on the copy.
//
// Existing Control or ControlContext hooks are rejected because replacing them
// is how safehttp enforces the post-DNS address policy.
func Dialer(dialer *net.Dialer) Option {
	return func(o *options) error {
		if dialer == nil {
			return fmt.Errorf("safehttp: dialer cannot be nil")
		}

		if dialer.Control != nil || dialer.ControlContext != nil {
			return fmt.Errorf("safehttp: dialer control hooks are owned by safehttp")
		}

		copied := *dialer
		o.dialer = &copied

		return nil
	}
}

// ClientTimeout sets http.Client.Timeout on clients built by NewClient.
func ClientTimeout(timeout time.Duration) Option {
	return func(o *options) error {
		if timeout < 0 {
			return fmt.Errorf("safehttp: client timeout cannot be negative")
		}

		o.clientTimeout = timeout

		return nil
	}
}

// MaxResponseHeaderBytes sets http.Transport.MaxResponseHeaderBytes.
func MaxResponseHeaderBytes(n int64) Option {
	return func(o *options) error {
		if n < 0 {
			return fmt.Errorf("safehttp: max response header bytes cannot be negative")
		}

		o.maxResponseHeader = n

		return nil
	}
}

// MaxResponseBytes caps the number of response body bytes a caller may read.
//
// The limit is enforced while the caller reads the response body. safehttp does
// not buffer the body up front.
func MaxResponseBytes(n int64) Option {
	return func(o *options) error {
		if n < 0 {
			return fmt.Errorf("safehttp: max response bytes cannot be negative")
		}

		o.maxResponseBytes = n

		return nil
	}
}
