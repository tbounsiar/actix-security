# Channel Security

Channel security ensures that certain URLs are only accessible over secure (HTTPS) connections, automatically redirecting HTTP requests to HTTPS when needed.

## Basic Usage

Channel security is always available (no feature flag needed):

```rust
use actix_security::http::security::{ChannelSecurity, ChannelSecurityConfig};
use actix_web::{App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let channel_security = ChannelSecurity::new(
        ChannelSecurityConfig::new()
            .require_secure("/login")
            .require_secure("/admin/**")
            .require_secure("/api/payments/**")
    );

    HttpServer::new(move || {
        App::new()
            .wrap(channel_security.clone())
            // ... routes
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Configuration Options

```rust
ChannelSecurityConfig::new()
    // Require HTTPS for specific paths (supports ant-style patterns)
    .require_secure("/login")
    .require_secure("/admin/**")
    .require_secure("/api/*/sensitive")

    // Require HTTP for specific paths (optional, for debugging)
    .require_insecure("/health")
    .require_insecure("/metrics")

    // Allow both HTTP and HTTPS
    .any_channel("/public/**")

    // Configure port mapping for redirects
    .port_mapper(PortMapper::new()
        .map(80, 443)
        .map(8080, 8443))

    // Redirect status code (default: 302)
    .redirect_status(StatusCode::MOVED_PERMANENTLY)  // 301
```

## Channel Requirements

Three types of channel requirements:

```rust
use actix_security::http::security::ChannelRequirement;

// Require HTTPS
ChannelRequirement::Secure

// Require HTTP (rarely used)
ChannelRequirement::Insecure

// Allow both
ChannelRequirement::Any
```

## HTTPS for All Routes

To require HTTPS for the entire application:

```rust
let channel_security = ChannelSecurity::new(
    ChannelSecurityConfig::new()
        .require_secure("/**")
        .except("/health")  // Except health checks
);
```

## Port Mapping

Configure port mapping for proper redirects:

```rust
use actix_security::http::security::PortMapper;

// Standard ports
let mapper = PortMapper::default();  // 80 -> 443

// Custom ports (e.g., development)
let mapper = PortMapper::new()
    .map(8080, 8443)
    .map(3000, 3443);

ChannelSecurityConfig::new()
    .port_mapper(mapper)
```

## Behind a Reverse Proxy

When behind a reverse proxy (nginx, load balancer), use the `X-Forwarded-Proto` header:

```rust
ChannelSecurityConfig::new()
    .trust_proxy_headers(true)  // Trust X-Forwarded-Proto
    .require_secure("/api/**")
```

This checks the `X-Forwarded-Proto` header instead of the actual connection protocol.

## Redirect Behavior

When an HTTP request is made to a secure-only path:

1. The middleware intercepts the request
2. Constructs an HTTPS URL with the same path and query string
3. Returns a redirect response (302 by default)

Example:
- Request: `http://example.com/login?next=/dashboard`
- Redirect: `https://example.com/login?next=/dashboard`

## Conditional Channel Security

Apply channel security based on environment:

```rust
let config = if std::env::var("PRODUCTION").is_ok() {
    ChannelSecurityConfig::new()
        .require_secure("/**")
} else {
    // Development: no HTTPS requirement
    ChannelSecurityConfig::new()
        .any_channel("/**")
};
```

## Combining with Security Headers

Often used together with HSTS:

```rust
use actix_security::http::security::{ChannelSecurity, SecurityHeaders};

App::new()
    .wrap(channel_security)
    .wrap(SecurityHeaders::default())  // Includes HSTS
```

## Error Responses

When redirect is not possible (e.g., POST request):

```rust
ChannelSecurityConfig::new()
    .require_secure("/api/**")
    .on_insecure_request(|req| {
        // Return 403 instead of redirect for API calls
        HttpResponse::Forbidden()
            .body("HTTPS required for API access")
    })
```

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| `requiresChannel()` | `ChannelSecurityConfig` |
| `.requiresSecure()` | `.require_secure()` |
| `.requiresInsecure()` | `.require_insecure()` |
| `.anyRequest().requiresSecure()` | `.require_secure("/**")` |
| `PortMapper` | `PortMapper` |
| `ChannelDecisionManager` | `ChannelSecurity` middleware |

## Example: E-Commerce Security

```rust
ChannelSecurityConfig::new()
    // All authentication must be secure
    .require_secure("/login")
    .require_secure("/register")
    .require_secure("/forgot-password")

    // All account pages must be secure
    .require_secure("/account/**")

    // All payment processing must be secure
    .require_secure("/checkout/**")
    .require_secure("/api/payments/**")

    // Admin area must be secure
    .require_secure("/admin/**")

    // Public pages can use either
    .any_channel("/products/**")
    .any_channel("/search")
```

## Best Practices

1. **Production**: Require HTTPS for all routes (`/**`)
2. **Sensitive Data**: Always require HTTPS for login, payments, personal data
3. **HSTS**: Combine with HSTS header for additional security
4. **Monitoring**: Exclude health check endpoints from HTTPS requirement
5. **API**: Return 403 instead of redirect for API endpoints
6. **Development**: Use self-signed certificates or disable in development only
