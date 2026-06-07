# safehttp

[![Go Reference](https://pkg.go.dev/badge/github.com/ayuhito/safehttp.svg)](https://pkg.go.dev/github.com/ayuhito/safehttp)

`safehttp` is an SSRF-resistant wrapper around Go's `net/http` for outbound
requests whose URL is provided by an untrusted source.

Use it when your service fetches URLs from users, webhooks, OAuth metadata,
imported documents, third-party API payloads, or any other source you do not
fully control. It keeps those requests constrained to allowed public
destinations and blocks loopback, RFC1918 networks, Kubernetes, cloud metadata,
and other internal or special-use addresses.

## Defaults

`NewClient()` starts with a public-HTTPS-only configuration.

Requests must use HTTPS, target a public destination, and use port `443`. URL
credentials, custom `Request.Host`, proxies, other schemes or ports, and
internal or special-use IP ranges are blocked.

Redirects are followed by default, but every redirect target is revalidated.

## Install

```sh
go get github.com/ayuhito/safehttp
```

## Usage

Create one client and reuse it.

```go
client, err := safehttp.NewClient(
	safehttp.ClientTimeout(5*time.Second),
	safehttp.MaxResponseBytes(10<<20),
	safehttp.NoRedirects(),
)
if err != nil {
	return err
}

resp, err := client.Get(rawURL)
if err != nil {
	return err
}
defer resp.Body.Close()
```

If the trusted destination is a known base URL, allow its exact origin. The
path, query string, and fragment are ignored. The policy is the normalized
scheme, host, and effective port.

```go
client, err := safehttp.NewClient(
	safehttp.AllowOrigins("https://api.example.com"),
	safehttp.AllowMethods(http.MethodGet),
	safehttp.MaxRedirects(3),
	safehttp.ClientTimeout(5*time.Second),
	safehttp.MaxResponseBytes(8<<20),
)
```

`AllowOrigins` is an exact tuple policy. Multiple origins do not create
cross-product allowances between schemes, hosts, and ports. Address checks still
apply, so loopback or private test servers require an explicit `AllowCIDRs`
opt-in.

Use `AllowHosts` when the policy is genuinely host-pattern based, such as
multiple exact hosts or a wildcard domain family. Pair it with explicit schemes
and ports.

```go
client, err := safehttp.NewClient(
	safehttp.AllowHosts(
		"api.github.com",
		"uploads.github.com",
		"*.githubusercontent.com",
	),
	safehttp.AllowSchemes("https"),
	safehttp.AllowPorts(443),
	safehttp.AllowMethods(http.MethodGet, http.MethodHead),
	safehttp.MaxRedirects(3),
	safehttp.ClientTimeout(5*time.Second),
	safehttp.MaxResponseBytes(8<<20),
)
```

## Existing Transports

Use `NewTransport` to reuse an existing transport configuration.

```go
base := http.DefaultTransport.(*http.Transport).Clone()
base.MaxIdleConnsPerHost = 32

rt, err := safehttp.NewTransport(base, safehttp.AllowOrigins("https://api.github.com"))
if err != nil {
	return err
}

client := &http.Client{Transport: rt}
```

`safehttp` clones the transport before applying its settings, so the original
transport is not modified. Use `safehttp.Dialer` for custom dialer settings.
Transport settings that bypass safehttp's connection checks or disable TLS
certificate verification are rejected.

## Guard-Only Checks

`NewGuard` exposes validation without constructing an `http.Client`.

```go
guard, err := safehttp.NewGuard(safehttp.AllowOrigins("https://api.github.com"))
if err != nil {
	return err
}

if err := guard.CheckRequest(req); err != nil {
	return err
}
```

Use guard-only checks for preflight validation. They do not send the request;
use `NewClient` or `NewTransport` for the outbound HTTP path.

## API Reference

Constructors:

```go
func NewClient(opts ...Option) (*http.Client, error)
func NewTransport(base *http.Transport, opts ...Option) (http.RoundTripper, error)
func NewGuard(opts ...Option) (*Guard, error)
```

Options:

- exact destination policy: `AllowOrigins`
- component destination policy: `AllowHosts`, `AllowSchemes`, `AllowPorts`
- request policy: `AllowMethods`
- redirects: `MaxRedirects`, `NoRedirects`
- explicit opt-ins: `AllowCredentials`, `AllowCustomHostHeader`
- address policy: `AllowPrefixes`, `DenyPrefixes`, `AllowCIDRs`, `DenyCIDRs`
- transport/client limits: `Dialer`, `ClientTimeout`, `MaxResponseHeaderBytes`, `MaxResponseBytes`

`AllowPrefixes` and `AllowCIDRs` opt in to additional address ranges, for
example private infrastructure or local tests. `DenyPrefixes` and `DenyCIDRs`
make the address policy stricter. Deny rules are evaluated before allow rules.

## Acknowledgements

This library was inspired by and borrows from the following projects:

- [`doyensec/safeurl`](https://github.com/doyensec/safeurl)
- [`daenney/ssrf`](https://github.com/daenney/ssrf)
