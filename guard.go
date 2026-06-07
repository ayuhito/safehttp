package safehttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"
)

// Guard validates outbound HTTP requests, redirects, and dialed addresses.
type Guard struct {
	schemes           map[string]struct{}
	ports             []uint16
	hosts             hostMatcher
	origins           originMatcher
	methods           map[string]struct{}
	maxRedirects      int
	allowCredentials  bool
	allowCustomHost   bool
	customAllowV4     []netip.Prefix
	customAllowV6     []netip.Prefix
	customDenyV4      []netip.Prefix
	customDenyV6      []netip.Prefix
	dialer            *net.Dialer
	clientTimeout     time.Duration
	maxResponseHeader int64
	maxResponseBytes  int64
}

// NewGuard compiles options into a reusable concurrency-safe guard.
func NewGuard(opts ...Option) (*Guard, error) {
	cfg := options{
		schemes:      []string{"https"},
		ports:        []uint16{443},
		maxRedirects: 10,
	}

	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("safehttp: option cannot be nil")
		}

		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}

	g := &Guard{
		maxRedirects:      cfg.maxRedirects,
		allowCredentials:  cfg.allowCredentials,
		allowCustomHost:   cfg.allowCustomHost,
		ports:             cfg.ports,
		dialer:            cfg.dialer,
		clientTimeout:     cfg.clientTimeout,
		maxResponseHeader: cfg.maxResponseHeader,
		maxResponseBytes:  cfg.maxResponseBytes,
	}

	var err error
	if cfg.explicitOrigins {
		if g.origins, err = compileOriginMatcher(cfg.origins); err != nil {
			return nil, err
		}

		g.ports = g.origins.ports
	} else {
		if g.schemes, err = compileSchemes(cfg.schemes); err != nil {
			return nil, err
		}

		if g.hosts, err = compileHostMatcher(cfg.hosts); err != nil {
			return nil, err
		}
	}

	if g.methods, err = compileMethods(cfg.methods); err != nil {
		return nil, err
	}

	g.customAllowV4, g.customAllowV6 = splitPrefixes(cfg.allowPrefixes)
	g.customDenyV4, g.customDenyV6 = splitPrefixes(cfg.denyPrefixes)

	return g, nil
}

// CheckURL validates a URL before it is used for an outbound request.
//
// This check works only from the parsed url.URL fields; callers should parse
// raw strings before handing them to safehttp. DNS names are intentionally not
// resolved here. Resolution happens inside the transport, and the resulting
// address is checked later by CheckAddr through net.Dialer.ControlContext.
func (g *Guard) CheckURL(u *url.URL) error {
	if u == nil {
		return &BlockError{Reason: "nil url", err: ErrInvalidURL}
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		return newURLBlockError(ErrInvalidURL, "missing scheme", u)
	}

	originMode := g.origins.configured()
	if !originMode {
		if _, ok := g.schemes[scheme]; !ok {
			block := newURLBlockError(ErrBlockedScheme, "scheme is not allowed", u)
			block.Scheme = scheme

			return block
		}
	}

	if u.User != nil && !g.allowCredentials {
		return newURLBlockError(ErrBlockedCredentials, "url credentials are not allowed", u)
	}

	host := u.Hostname()
	if host == "" {
		return newURLBlockError(ErrInvalidURL, "missing host", u)
	}

	port, err := effectivePort(u, scheme)
	if err != nil {
		block := newURLBlockError(ErrBlockedPort, err.Error(), u)
		block.Host = host

		return block
	}

	if !originMode && !slices.Contains(g.ports, port) {
		block := newURLBlockError(ErrBlockedPort, "port is not allowed", u)
		block.Host = host
		block.Port = port

		return block
	}

	// Host and origin policy is applied to normalized ASCII form. For IP
	// literal hosts, normalizeURLHost also returns the parsed address so we can
	// apply the same public-address policy immediately, before any transport is
	// involved.
	normalizedHost, addr, err := normalizeURLHost(host)
	if err != nil {
		block := newURLBlockError(ErrInvalidURL, err.Error(), u)
		block.Host = host
		block.Port = port

		return block
	}

	if originMode {
		if !g.origins.allows(origin{scheme: scheme, host: normalizedHost, port: port}) {
			block := newURLBlockError(ErrBlockedOrigin, "origin is not allowed", u)
			block.Scheme = scheme
			block.Host = normalizedHost
			block.Port = port

			return block
		}
	} else if !g.hosts.allows(normalizedHost) {
		block := newURLBlockError(ErrBlockedHost, "host is not allowed", u)
		block.Host = normalizedHost
		block.Port = port

		return block
	}

	if addr.IsValid() {
		network := "tcp6"
		if addr.Is4() {
			network = "tcp4"
		}

		if err := g.CheckAddr(network, netip.AddrPortFrom(addr, port)); err != nil {
			if block, ok := errors.AsType[*BlockError](err); ok {
				block.URL = redactURL(u)
				block.Host = normalizedHost
			}

			return err
		}
	}

	return nil
}

// CheckRequest validates an HTTP request before it is sent.
func (g *Guard) CheckRequest(req *http.Request) error {
	if req == nil {
		return &BlockError{Reason: "nil request", err: ErrInvalidURL}
	}

	if req.Host != "" && !g.allowCustomHost {
		// Setting Request.Host to the same authority the transport would send is
		// valid. Anything else is host-header smuggling and stays blocked unless
		// the caller explicitly opts in.
		matchesURL := false

		if req.URL != nil {
			scheme := strings.ToLower(req.URL.Scheme)
			hostURL := &url.URL{Scheme: scheme, Host: req.Host}

			if hostName := hostURL.Hostname(); hostName != "" {
				hostPort, hostPortErr := effectivePort(hostURL, scheme)
				urlPort, urlPortErr := effectivePort(req.URL, scheme)
				normalizedHost, _, hostErr := normalizeURLHost(hostName)
				normalizedURLHost, _, urlHostErr := normalizeURLHost(req.URL.Hostname())

				matchesURL = hostPortErr == nil &&
					urlPortErr == nil &&
					hostErr == nil &&
					urlHostErr == nil &&
					normalizedHost == normalizedURLHost &&
					hostPort == urlPort
			}
		}

		if !matchesURL {
			block := newURLBlockError(ErrBlockedHostHeader, "custom host header is not allowed", req.URL)
			block.Host = req.Host

			return block
		}
	}

	if err := g.CheckURL(req.URL); err != nil {
		return err
	}

	// An empty method means GET in net/http. Mirror that behavior before
	// applying any caller-provided method allowlist.
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}

	if len(g.methods) > 0 {
		if _, ok := g.methods[method]; !ok {
			block := newURLBlockError(ErrBlockedMethod, "method is not allowed", req.URL)
			block.Method = method

			return block
		}
	}

	return nil
}

// CheckAddr validates the concrete network address selected for dialing.
//
// This is the security boundary that matters after DNS resolution. A URL host
// like example.com may be syntactically fine, but the resolver can still return
// 127.0.0.1, 169.254.169.254, an RFC1918 address, or another special range.
// CheckAddr is used for both IP literal URLs and net.Dialer.ControlContext.
func (g *Guard) CheckAddr(network string, addr netip.AddrPort) error {
	if network != "tcp4" && network != "tcp6" {
		return &BlockError{Reason: "network is not allowed", Addr: addr, Rule: network, err: ErrBlockedNetwork}
	}

	if !addr.IsValid() {
		return &BlockError{Reason: "address is invalid", Addr: addr, err: ErrBlockedAddress}
	}

	if !slices.Contains(g.ports, addr.Port()) {
		return &BlockError{Reason: "port is not allowed", Port: addr.Port(), Addr: addr, err: ErrBlockedPort}
	}

	// Keep both forms for IPv4-mapped IPv6. Caller allow/deny policy is
	// evaluated against the unmapped IPv4 address, but the default policy still
	// blocks the mapped IPv6 special-purpose range unless the caller opts in.
	originalIP := addr.Addr()
	ip := originalIP.Unmap()

	// Caller denies are checked first so explicit block rules cannot be
	// weakened by a broader allow rule.
	if prefix, ok := containsPrefix(g.customDenyV4, g.customDenyV6, ip); ok {
		return &BlockError{Reason: "address is denied", Addr: addr, Rule: prefix.String(), err: ErrBlockedAddress}
	}

	// Allows are explicit opt-ins for local tests or private destinations. They
	// bypass the built-in special-purpose range policy.
	if _, ok := containsPrefix(g.customAllowV4, g.customAllowV6, ip); ok {
		return nil
	}

	// IPv4-mapped IPv6 is an IANA special-purpose range. Block it by default so
	// ::ffff:8.8.8.8 is not a second spelling for an otherwise public IPv4
	// literal, while still allowing explicit prefix opt-ins above.
	if originalIP.Is4In6() {
		return &BlockError{Reason: "address is ipv4-mapped ipv6", Addr: addr, Rule: "::ffff:0:0/96", err: ErrBlockedAddress}
	}

	// netip.IsGlobalUnicast is not enough for this policy: it returns true for
	// RFC1918 IPv4 and IPv6 ULA. Keep the public-destination checks explicit.
	switch {
	case ip.IsUnspecified():
		return &BlockError{Reason: "address is unspecified", Addr: addr, Rule: "unspecified", err: ErrBlockedAddress}
	case ip.IsLoopback():
		return &BlockError{Reason: "address is loopback", Addr: addr, Rule: "loopback", err: ErrBlockedAddress}
	case ip.IsPrivate():
		return &BlockError{Reason: "address is private", Addr: addr, Rule: "private", err: ErrBlockedAddress}
	case ip.IsLinkLocalUnicast():
		return &BlockError{Reason: "address is link-local", Addr: addr, Rule: "link-local", err: ErrBlockedAddress}
	case ip.IsMulticast():
		return &BlockError{Reason: "address is multicast", Addr: addr, Rule: "multicast", err: ErrBlockedAddress}
	case ip.Is6() && !ipv6GlobalUnicast.Contains(ip):
		return &BlockError{Reason: "ipv6 address is outside global unicast", Addr: addr, Rule: ipv6GlobalUnicast.String(), err: ErrBlockedAddress}
	}

	if prefix, ok := containsPrefix(specialDenyV4, specialDenyV6, ip); ok {
		return &BlockError{Reason: "address is blocked by default policy", Addr: addr, Rule: prefix.String(), err: ErrBlockedAddress}
	}

	return nil
}

// ControlContext implements net.Dialer.ControlContext.
func (g *Guard) ControlContext(_ context.Context, network, address string, _ syscall.RawConn) error {
	addr, err := netip.ParseAddrPort(address)
	if err != nil {
		return &BlockError{Reason: "dial address is invalid", Rule: address, err: ErrInvalidURL}
	}

	return g.CheckAddr(network, addr)
}

// CheckRedirect validates a redirect target for http.Client.CheckRedirect.
func (g *Guard) CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > g.maxRedirects {
		return newURLBlockError(ErrBlockedRedirect, "redirect limit exceeded", req.URL)
	}

	// Redirects are new outbound requests. Re-run the full request policy so a
	// safe first URL cannot bounce the client to HTTP, a private IP, a blocked
	// host, credentials, or a disallowed port.
	if err := g.CheckRequest(req); err != nil {
		if block, ok := errors.AsType[*BlockError](err); ok {
			block.err = errors.Join(ErrBlockedRedirect, block.err)
		}

		return err
	}

	return nil
}
