// Package safehttp is an SSRF-resistant wrapper around Go's net/http for
// outbound requests to URLs provided by users or external systems.
//
// Use it when a service fetches URLs from users, webhooks, OAuth metadata,
// imported documents, third-party API payloads, or any other source it does not
// fully control. safehttp keeps those requests constrained to allowed
// destinations and blocks loopback, private networks, cloud metadata, and other
// internal or special-use addresses.
//
// NewClient starts with a public-HTTPS-only configuration. Requests must use
// HTTPS, target a public destination, and use port 443. URL credentials, custom
// Request.Host values, proxies, other schemes or ports, and private or
// special-use IP ranges are blocked. Redirects are followed by default, but
// every redirect target is revalidated.
//
// NewGuard exposes URL and request validation without constructing an
// http.Client. Use guard-only checks for preflight validation; use NewClient or
// NewTransport for the outbound HTTP path.
package safehttp
