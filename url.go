package safehttp

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/http/httpguts"
)

type origin struct {
	scheme string
	host   string
	port   uint16
}

type originMatcher struct {
	origins map[origin]struct{}
	ports   []uint16
}

func compileOriginMatcher(rawOrigins []string) (originMatcher, error) {
	if len(rawOrigins) == 0 {
		return originMatcher{}, nil
	}

	matcher := originMatcher{
		origins: make(map[origin]struct{}, len(rawOrigins)),
	}

	for _, rawOrigin := range rawOrigins {
		normalized, err := normalizeOrigin(rawOrigin)
		if err != nil {
			return originMatcher{}, fmt.Errorf("safehttp: invalid origin %q: %w", rawOrigin, err)
		}

		matcher.origins[normalized] = struct{}{}
		if !slices.Contains(matcher.ports, normalized.port) {
			matcher.ports = append(matcher.ports, normalized.port)
		}
	}

	return matcher, nil
}

func normalizeOrigin(rawOrigin string) (origin, error) {
	rawOrigin = strings.TrimSpace(rawOrigin)
	if rawOrigin == "" {
		return origin{}, fmt.Errorf("origin cannot be empty")
	}

	u, err := url.Parse(rawOrigin)
	if err != nil {
		return origin{}, err
	}

	if u.User != nil {
		return origin{}, fmt.Errorf("origin must not include credentials")
	}

	scheme, err := normalizeScheme(u.Scheme)
	if err != nil {
		return origin{}, err
	}

	host := u.Hostname()
	if host == "" {
		return origin{}, fmt.Errorf("missing host")
	}

	if strings.Contains(host, "*") {
		return origin{}, fmt.Errorf("origin host must not include wildcards")
	}

	port, err := effectivePort(u, scheme)
	if err != nil {
		return origin{}, err
	}

	normalizedHost, _, err := normalizeURLHost(host)
	if err != nil {
		return origin{}, err
	}

	return origin{scheme: scheme, host: normalizedHost, port: port}, nil
}

func (m originMatcher) configured() bool {
	return len(m.origins) > 0
}

func (m originMatcher) allows(origin origin) bool {
	if !m.configured() {
		return true
	}

	_, ok := m.origins[origin]

	return ok
}

// normalizeScheme accepts URI schemes, not full URL prefixes.
//
// The public option is AllowSchemes("https"), so rejecting "https://",
// "https/example.com", and similar inputs catches common configuration
// mistakes at construction time instead of silently allowing the wrong thing.
func normalizeScheme(scheme string) (string, error) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme == "" {
		return "", fmt.Errorf("scheme cannot be empty")
	}

	if strings.Contains(scheme, "://") || strings.ContainsAny(scheme, "/:@") {
		return "", fmt.Errorf("scheme must not include url syntax")
	}

	if !isValidScheme(scheme) {
		return "", fmt.Errorf("scheme has invalid characters")
	}

	return scheme, nil
}

func compileSchemes(schemes []string) (map[string]struct{}, error) {
	set := make(map[string]struct{}, len(schemes))
	for _, scheme := range schemes {
		normalized, err := normalizeScheme(scheme)
		if err != nil {
			return nil, fmt.Errorf("safehttp: invalid scheme %q: %w", scheme, err)
		}

		set[normalized] = struct{}{}
	}

	return set, nil
}

func normalizeMethod(method string) (string, error) {
	method = strings.TrimSpace(method)
	if method == "" {
		return "", fmt.Errorf("method cannot be empty")
	}

	// HTTP methods use the HTTP "token" grammar.
	//
	// Source: https://www.rfc-editor.org/rfc/rfc9110#section-5.6.2
	if !httpguts.ValidHeaderFieldName(method) {
		return "", fmt.Errorf("method has invalid token characters")
	}

	return method, nil
}

func compileMethods(methods []string) (map[string]struct{}, error) {
	if len(methods) == 0 {
		return nil, nil
	}

	set := make(map[string]struct{}, len(methods))
	for _, method := range methods {
		normalized, err := normalizeMethod(method)
		if err != nil {
			return nil, fmt.Errorf("safehttp: invalid method %q: %w", method, err)
		}

		set[normalized] = struct{}{}
	}

	return set, nil
}

// effectivePort returns the port a transport would use for this URL.
//
// url.URL.Port cannot distinguish "no port was provided" from some malformed
// host:port forms, so this function checks for obvious bad port syntax before
// falling back to scheme defaults.
//
// Source: https://pkg.go.dev/net/url#URL.Port
func effectivePort(u *url.URL, scheme string) (uint16, error) {
	port := u.Port()
	if port != "" {
		parsed, err := strconv.ParseUint(port, 10, 16)
		if err != nil || parsed == 0 {
			return 0, fmt.Errorf("port is invalid")
		}

		return uint16(parsed), nil
	}

	// Inspect Host before applying a scheme default so malformed port suffixes
	// do not become an implicit 443 or 80.
	host := u.Host
	if strings.HasPrefix(host, "[") {
		if _, after, ok := strings.Cut(host, "]"); ok && strings.HasPrefix(after, ":") {
			return 0, fmt.Errorf("port is invalid")
		}
	} else if before, after, ok := strings.Cut(host, ":"); ok && before != "" && !strings.Contains(after, ":") {
		return 0, fmt.Errorf("port is invalid")
	}

	switch scheme {
	case "https":
		return 443, nil
	case "http":
		return 80, nil
	default:
		return 0, fmt.Errorf("port is required for scheme %q", scheme)
	}
}

func isValidScheme(scheme string) bool {
	// URI scheme grammar is ASCII-only: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ).
	// unicode.IsLetter or unicode.IsDigit would accept non-ASCII schemes.
	//
	// Source: https://www.rfc-editor.org/rfc/rfc3986#section-3.1
	for i, r := range scheme {
		if r > unicode.MaxASCII {
			return false
		}

		if i == 0 {
			if !unicode.IsLetter(r) {
				return false
			}

			continue
		}

		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '+' || r == '-' || r == '.' {
			continue
		}

		return false
	}

	return true
}

// redactURL removes parts of a URL that commonly contain secrets.
//
// BlockError may be logged or returned to callers. The scheme, host, path, and
// port are retained for diagnosis. Credentials, query strings, and fragments are
// removed because they often contain tokens or user data.
func redactURL(u *url.URL) string {
	if u == nil {
		return ""
	}

	redacted := *u
	redacted.User = nil
	redacted.RawQuery = ""
	redacted.Fragment = ""

	return redacted.String()
}
