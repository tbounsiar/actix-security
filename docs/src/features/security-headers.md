# Security Headers

Protect your application with HTTP security headers middleware.

## Overview

`SecurityHeaders` middleware adds important security headers to all responses:

- **X-Content-Type-Options** - Prevents MIME sniffing
- **X-Frame-Options** - Protects against clickjacking
- **X-XSS-Protection** - Legacy XSS protection
- **Content-Security-Policy** - Controls resource loading
- **Strict-Transport-Security** - Enforces HTTPS
- **Referrer-Policy** - Controls referrer information
- **Permissions-Policy** - Controls browser features
- **Cache-Control** - Controls caching behavior

## Quick Start

```rust
use actix_security::http::security::SecurityHeaders;

App::new()
    .wrap(SecurityHeaders::default())
    .service(/* ... */)
```

## Default Configuration

```rust
SecurityHeaders::default()
```

Adds these headers:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0
Referrer-Policy: strict-origin-when-cross-origin
```

## Strict Configuration

```rust
SecurityHeaders::strict()
```

Maximum security with all headers:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=()
Cache-Control: no-cache, no-store, must-revalidate
```

## Custom Configuration

### X-Frame-Options

Protect against clickjacking:

```rust
use actix_security::http::security::headers::FrameOptions;

// Block all framing (default)
SecurityHeaders::new().frame_options(FrameOptions::Deny)

// Allow same origin
SecurityHeaders::new().frame_options(FrameOptions::SameOrigin)

// Disable header
SecurityHeaders::new().frame_options(FrameOptions::Disabled)
```

### Content-Security-Policy

Control resource loading:

```rust
// Basic policy
SecurityHeaders::new()
    .content_security_policy("default-src 'self'")

// More permissive
SecurityHeaders::new()
    .content_security_policy("default-src 'self'; img-src *; script-src 'self' cdn.example.com")

// Complex policy
SecurityHeaders::new()
    .content_security_policy(
        "default-src 'self'; \
         script-src 'self' 'unsafe-inline' cdn.example.com; \
         style-src 'self' 'unsafe-inline'; \
         img-src 'self' data: https:; \
         font-src 'self' fonts.gstatic.com; \
         connect-src 'self' api.example.com"
    )
```

### Strict-Transport-Security (HSTS)

Enforce HTTPS:

```rust
// Enable with 1 year max-age
SecurityHeaders::new().hsts(true, 31536000)

// With subdomains
SecurityHeaders::new()
    .hsts(true, 31536000)
    .hsts_include_subdomains(true)

// With preload (for HSTS preload list)
SecurityHeaders::new()
    .hsts(true, 31536000)
    .hsts_include_subdomains(true)
    .hsts_preload(true)
```

> **Warning**: Only enable HSTS preload if you're committed to HTTPS forever. It's difficult to reverse.

### Referrer-Policy

Control referrer information:

```rust
use actix_security::http::security::headers::ReferrerPolicy;

// No referrer (maximum privacy)
SecurityHeaders::new().referrer_policy(ReferrerPolicy::NoReferrer)

// Same origin only
SecurityHeaders::new().referrer_policy(ReferrerPolicy::SameOrigin)

// Strict origin when cross-origin (default)
SecurityHeaders::new().referrer_policy(ReferrerPolicy::StrictOriginWhenCrossOrigin)

// No referrer when downgrade
SecurityHeaders::new().referrer_policy(ReferrerPolicy::NoReferrerWhenDowngrade)
```

### Permissions-Policy

Control browser features:

```rust
// Disable geolocation, microphone, camera
SecurityHeaders::new()
    .permissions_policy("geolocation=(), microphone=(), camera=()")

// Allow geolocation for self only
SecurityHeaders::new()
    .permissions_policy("geolocation=(self), microphone=(), camera=()")
```

### Cache-Control

Control caching:

```rust
// No caching (for sensitive data)
SecurityHeaders::new()
    .cache_control("no-cache, no-store, must-revalidate")

// Private caching
SecurityHeaders::new()
    .cache_control("private, max-age=3600")
```

## Complete Example

```rust
use actix_web::{get, App, HttpServer, HttpResponse, Responder};
use actix_security::http::security::SecurityHeaders;
use actix_security::http::security::headers::{FrameOptions, ReferrerPolicy};

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(
                SecurityHeaders::new()
                    .frame_options(FrameOptions::SameOrigin)
                    .content_security_policy("default-src 'self'; img-src *")
                    .hsts(true, 31536000)
                    .hsts_include_subdomains(true)
                    .referrer_policy(ReferrerPolicy::StrictOriginWhenCrossOrigin)
                    .permissions_policy("geolocation=(), microphone=(), camera=()")
                    .cache_control("no-cache")
            )
            .service(index)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Middleware Order

Place `SecurityHeaders` after authentication middleware but before your routes:

```rust
App::new()
    .wrap(SecurityHeaders::default())  // Adds security headers
    .wrap(SecurityTransform::new()     // Handles auth
        .config_authenticator(/* ... */)
        .config_authorizer(/* ... */))
    .service(/* ... */)
```

## Testing

```rust
use actix_web::{test, App, http::StatusCode};

#[actix_web::test]
async fn test_security_headers() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeaders::default())
            .service(test_endpoint)
    ).await;

    let req = test::TestRequest::get().uri("/test").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);

    let headers = resp.headers();
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
}
```

## Spring Security Comparison

**Spring Security:**
```java
http.headers(headers -> headers
    .frameOptions(frame -> frame.deny())
    .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"))
    .httpStrictTransportSecurity(hsts -> hsts
        .maxAgeInSeconds(31536000)
        .includeSubDomains(true))
    .referrerPolicy(referrer -> referrer
        .policy(ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
);
```

**Actix Security:**
```rust
SecurityHeaders::new()
    .frame_options(FrameOptions::Deny)
    .content_security_policy("default-src 'self'")
    .hsts(true, 31536000)
    .hsts_include_subdomains(true)
    .referrer_policy(ReferrerPolicy::StrictOriginWhenCrossOrigin)
```

## Security Recommendations

| Header | Recommended Value | Notes |
|--------|-------------------|-------|
| X-Content-Type-Options | `nosniff` | Always enable |
| X-Frame-Options | `DENY` or `SAMEORIGIN` | Prevent clickjacking |
| Content-Security-Policy | App-specific | Start strict, relax as needed |
| Strict-Transport-Security | `max-age=31536000` | Only for HTTPS sites |
| Referrer-Policy | `strict-origin-when-cross-origin` | Balance privacy/functionality |
| Permissions-Policy | Disable unused features | Camera, mic, geolocation |
