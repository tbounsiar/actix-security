# Security Headers Example

This example demonstrates security headers middleware using the actix-security library.

## Quick Start

Add these dependencies to your `Cargo.toml`:

```toml
[dependencies]
actix-web = "4"
actix-security = "0.2"  # Security headers are always available (no feature flag needed)
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Features

- Content Security Policy (CSP)
- X-Frame-Options (Clickjacking protection)
- X-Content-Type-Options (MIME sniffing protection)
- Strict-Transport-Security (HSTS)
- Referrer-Policy
- Permissions-Policy
- Cache-Control for sensitive content

## Running the Example

```bash
# From the project root
cargo run --bin security_headers

# Or from the examples directory
cargo run -p actix-security-examples --bin security_headers
```

The server will start at `http://localhost:8080`.

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | Home page with all headers |
| `/api/data` | API endpoint with CORS headers |
| `/strict` | Endpoint with strict CSP |
| `/relaxed` | Endpoint with relaxed CSP |

## Testing

### Check Response Headers

```bash
# View all response headers
curl -I http://localhost:8080/

# Expected headers:
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# X-XSS-Protection: 1; mode=block
# Content-Security-Policy: default-src 'self'; ...
# Referrer-Policy: strict-origin-when-cross-origin
# Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### Browser DevTools

1. Open Chrome/Firefox DevTools (F12)
2. Go to Network tab
3. Navigate to `http://localhost:8080`
4. Click on the request
5. View "Response Headers" section

## Code Overview

```rust
// Strict security headers (recommended for most apps)
let headers = SecurityHeaders::strict();

// Or customize headers
let headers = SecurityHeaders::new()
    .x_frame_options(XFrameOptions::Deny)
    .x_content_type_options(true)
    .x_xss_protection(XssProtection::EnableBlock)
    .content_security_policy(ContentSecurityPolicy::new()
        .default_src(&["'self'"])
        .script_src(&["'self'", "https://trusted.cdn.com"])
        .style_src(&["'self'", "'unsafe-inline'"])
        .img_src(&["'self'", "data:", "https:"])
        .frame_ancestors(&["'none'"])
    )
    .strict_transport_security(Hsts::new()
        .max_age(Duration::from_secs(31536000))
        .include_subdomains(true)
    )
    .referrer_policy(ReferrerPolicy::StrictOriginWhenCrossOrigin)
    .permissions_policy(PermissionsPolicy::new()
        .camera(&["'none'"])
        .microphone(&["'none'"])
        .geolocation(&["'self'"])
    );

// Apply to app
App::new()
    .wrap(headers)
```

## Security Headers Explained

### X-Frame-Options

Prevents clickjacking by controlling if the page can be embedded in iframes.

| Value | Description |
|-------|-------------|
| `DENY` | Never allow framing |
| `SAMEORIGIN` | Only allow same-origin framing |
| `ALLOW-FROM url` | Allow specific origin (deprecated) |

### Content-Security-Policy

Controls which resources the browser can load.

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' https://trusted.cdn.com;
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self' https://fonts.googleapis.com;
  connect-src 'self' https://api.example.com;
  frame-ancestors 'none'
```

### Strict-Transport-Security (HSTS)

Forces HTTPS connections.

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### Referrer-Policy

Controls referrer information sent with requests.

| Value | Description |
|-------|-------------|
| `no-referrer` | Never send referrer |
| `strict-origin-when-cross-origin` | Send origin for cross-origin requests |
| `same-origin` | Only send for same-origin requests |

### Permissions-Policy

Controls browser features.

```
Permissions-Policy: camera=(), microphone=(), geolocation=(self)
```

## Spring Security Equivalent

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .headers()
                .frameOptions().deny()
                .xssProtection().block(true)
                .contentTypeOptions()
                .and()
                .contentSecurityPolicy("default-src 'self'")
                .and()
                .httpStrictTransportSecurity()
                    .maxAgeInSeconds(31536000)
                    .includeSubDomains(true)
                .and()
                .referrerPolicy(ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                .and()
                .permissionsPolicy(policy -> policy.policy("camera=(), microphone=()"));
    }
}
```

## Preset Configurations

| Preset | Description |
|--------|-------------|
| `SecurityHeaders::strict()` | Most restrictive, recommended for production |
| `SecurityHeaders::standard()` | Balanced security for most applications |
| `SecurityHeaders::api()` | Optimized for API servers |
| `SecurityHeaders::new()` | Start from scratch, customize everything |

## Related Examples

- [Security Complete](../security_complete/README.md) - All features combined
- [Form Login](../form_login/README.md) - Form-based authentication with headers
