# Case 19: SSRF via Custom RoundTripper Transport

**CWE:** CWE-918 (Server-Side Request Forgery)

## Vulnerability

User-controlled `url` query parameter is passed to `client.Get(target)` where `client` is an `*http.Client` with a custom `LoggingTransport`. An attacker requests:

```
/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

The custom transport only adds logging — it doesn't validate the destination. The request reaches internal infrastructure.

## Why Semgrep Misses It

Semgrep's SSRF rules for Go match patterns like `http.Get(userInput)` or `client.Get(userInput)` where `client` is a standard `*http.Client`. When the client is constructed through a factory function (`NewHTTPClient()`) that returns a client with a custom `Transport`, Semgrep's analysis faces two obstacles:

1. **Cross-file factory pattern**: The `client` variable is initialized via `NewHTTPClient()` in `transport.go`, making it harder to determine its type in `handler.go`
2. **Custom transport confusion**: The `LoggingTransport` wrapper around `http.DefaultTransport` makes the HTTP client non-standard. Rules matching `http.Client` methods may not fire when the client was created through an intermediate constructor

The logging transport could theoretically be a security proxy, but Semgrep has no way to determine that it doesn't perform URL validation.

## Detection Requirements

- Cross-file taint tracking from query parameter to HTTP client method call
- Recognition that `(*http.Client).Get()` is an SSRF sink regardless of transport configuration
- Factory function return type analysis
