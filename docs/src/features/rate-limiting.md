# Rate Limiting

Rate limiting protects your application from brute-force attacks, denial-of-service (DoS) attempts, and excessive API usage.

## Enabling Rate Limiting

Add the `rate-limit` feature to your `Cargo.toml`:

```toml
[dependencies]
actix-security = { version = "0.2", features = ["rate-limit"] }
```

## Basic Usage

```rust
use actix_security::http::security::{RateLimiter, RateLimitConfig};
use actix_web::{App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let rate_limiter = RateLimiter::new(
        RateLimitConfig::new()
            .requests_per_minute(60)
    );

    HttpServer::new(move || {
        App::new()
            .wrap(rate_limiter.clone())
            // ... routes
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Configuration Options

```rust
RateLimitConfig::new()
    // Maximum requests per window
    .max_requests(100)

    // Time window
    .window(Duration::from_secs(60))

    // Shorthand for requests_per_minute
    .requests_per_minute(60)

    // Burst capacity (for token bucket)
    .burst_size(10)

    // Algorithm selection
    .algorithm(RateLimitAlgorithm::SlidingWindow)

    // Add rate limit headers to response
    .add_headers(true)

    // Exclude certain paths
    .exclude_paths(vec!["/health", "/metrics"])
```

## Algorithms

### Fixed Window

Counts requests in fixed time intervals. Simple but can allow bursts at window boundaries.

```rust
.algorithm(RateLimitAlgorithm::FixedWindow)
```

### Sliding Window

Smooths out the window boundary issue by considering a weighted average.

```rust
.algorithm(RateLimitAlgorithm::SlidingWindow)
```

### Token Bucket

Allows controlled bursting while maintaining overall rate limits.

```rust
.algorithm(RateLimitAlgorithm::TokenBucket)
.burst_size(10)  // Allow burst of 10 requests
```

## Key Extraction

Rate limiting can be applied per IP address, per user, or with custom logic:

```rust
use actix_security::http::security::KeyExtractor;

RateLimitConfig::new()
    .key_extractor(KeyExtractor::IpAddress)      // Per IP (default)
    .key_extractor(KeyExtractor::User)           // Per authenticated user
    .key_extractor(KeyExtractor::IpAndEndpoint)  // Per IP + endpoint
    .key_extractor(KeyExtractor::Header("X-API-Key".to_string()))  // Per API key
```

## Response Headers

When `add_headers` is enabled, the following headers are added:

- `X-RateLimit-Limit`: Maximum requests allowed
- `X-RateLimit-Remaining`: Requests remaining in current window
- `X-RateLimit-Reset`: Unix timestamp when the window resets

## Preset Configurations

```rust
// Strict for login endpoints (5/minute)
RateLimitConfig::strict_login()

// Lenient for API (1000/minute)
RateLimitConfig::lenient_api()
```

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| Custom filter or Bucket4j | `RateLimiter` middleware |
| `@RateLimiter` annotation | Configuration-based |
