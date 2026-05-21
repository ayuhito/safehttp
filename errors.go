package safehttp

import (
	"errors"
	"net/netip"
	"net/url"
	"strings"
)

var (
	ErrBlocked            = errors.New("safehttp: blocked request")
	ErrInvalidURL         = errors.New("safehttp: invalid url")
	ErrBlockedScheme      = errors.New("safehttp: blocked scheme")
	ErrBlockedHost        = errors.New("safehttp: blocked host")
	ErrBlockedPort        = errors.New("safehttp: blocked port")
	ErrBlockedMethod      = errors.New("safehttp: blocked method")
	ErrBlockedAddress     = errors.New("safehttp: blocked address")
	ErrBlockedNetwork     = errors.New("safehttp: blocked network")
	ErrBlockedRedirect    = errors.New("safehttp: blocked redirect")
	ErrBlockedCredentials = errors.New("safehttp: blocked credentials")
	ErrBlockedHostHeader  = errors.New("safehttp: blocked host header")
	ErrBlockedTransport   = errors.New("safehttp: blocked transport")
)

// BlockError describes a request, redirect, address, or response blocked by safehttp.
type BlockError struct {
	// Reason is a short human-readable explanation of the decision.
	Reason string

	// URL is redacted before storage. It never includes URL credentials,
	// query strings, or fragments.
	URL string

	// Scheme, Host, Port, Method, and Addr identify the checked input when they
	// are known. Some errors only have one or two of these fields populated.
	Scheme string
	Host   string
	Port   uint16
	Method string
	Addr   netip.AddrPort

	// Rule is diagnostic detail for the matched policy rule, such as a denied
	// prefix, "private", "loopback", or a blocked network name. Use errors.Is
	// with the ErrBlocked* sentinels for stable control flow.
	Rule string

	err error
}

func (e *BlockError) Error() string {
	if e.Reason != "" {
		return "safehttp: " + e.Reason
	}

	return ErrBlocked.Error()
}

func (e *BlockError) Unwrap() error {
	return e.err
}

func (e *BlockError) Is(target error) bool {
	return target == ErrBlocked
}

func newURLBlockError(kind error, reason string, u *url.URL) *BlockError {
	err := &BlockError{
		Reason: reason,
		URL:    redactURL(u),
		err:    kind,
	}

	if u != nil {
		err.Scheme = strings.ToLower(u.Scheme)
		err.Host = u.Hostname()
	}

	return err
}
