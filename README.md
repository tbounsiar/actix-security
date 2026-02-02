# Actix Security

[![Crates.io](https://img.shields.io/crates/v/actix-security)](https://crates.io/crates/actix-security)
[![Documentation](https://docs.rs/actix-security/badge.svg)](https://docs.rs/actix-security)
[![License: MIT/Apache-2.0](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

**Spring Security-inspired authentication and authorization for Actix Web.**

Actix Security brings the power and familiarity of Spring Security to Rust, providing a comprehensive, declarative approach to securing your web applications.

## Features

### Core Security
- **Declarative Security** - Attribute macros like `#[secured]`, `#[pre_authorize]`, `#[permit_all]`
- **Expression Language** - Write rules like `hasRole('ADMIN') OR hasAuthority('users:write')`
- **Compile-Time Validation** - Security expressions are validated at build time
- **Pluggable Architecture** - Easy to extend with custom authenticators and authorizers

### Authentication Methods
- **HTTP Basic** - Standard HTTP Basic authentication (RFC 7617)
- **JWT** - Stateless token-based authentication with RSA support and refresh tokens
- **Session** - Server-side session management with session fixation protection
- **Form Login** - Spring-like form-based authentication with redirect support
- **Remember-Me** - Persistent login functionality
- **OAuth2 / OIDC** - Social login (Google, GitHub, etc.) and enterprise SSO
- **LDAP** - LDAP/Active Directory authentication
- **SAML 2.0** - Enterprise Single Sign-On with support for Okta, Azure AD, ADFS

### Security Features
- **CSRF Protection** - Token-based CSRF protection middleware
- **Rate Limiting** - Brute-force protection with configurable algorithms (Fixed Window, Sliding Window, Token Bucket)
- **Account Locking** - Automatic account lockout after failed attempts with progressive delays
- **Audit Logging** - Security event logging with JSON support
- **Security Headers** - Built-in middleware for CSP, HSTS, X-Frame-Options, etc.
- **Channel Security** - HTTPS enforcement and redirect

### Password Encoding
- **Argon2** - Recommended password hashing algorithm
- **BCrypt** - Compatible with existing BCrypt hashes
- **Delegating Encoder** - Automatic encoder detection from hash prefix

### Utilities
- **AntMatcher** - Spring-style URL pattern matching (`/api/**`, `/users/*/profile`)
- **UserDetailsService** - Async trait for loading users from any source
- **Security Context** - Access current user from anywhere

## Quick Start

Add dependencies to your `Cargo.toml`:

```toml
[dependencies]
actix-web = "4"
actix-security = { version = "0.2", features = ["argon2", "http-basic"] }
```

Create a secured application:

```rust
use actix_web::{get, post, App, HttpServer, HttpResponse, Responder};
use actix_security::{secured, pre_authorize};
use actix_security::http::security::{
    AuthenticatedUser, AuthenticationManager, AuthorizationManager,
    Argon2PasswordEncoder, PasswordEncoder, User,
};
use actix_security::http::security::middleware::SecurityTransform;

#[secured("ADMIN")]
#[get("/admin")]
async fn admin(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Welcome, Admin {}!", user.get_username()))
}

#[pre_authorize("hasRole('USER') AND hasAuthority('posts:write')")]
#[post("/posts")]
async fn create_post(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Created().body("Post created")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let encoder = Argon2PasswordEncoder::new();

    HttpServer::new(move || {
        let enc = encoder.clone();
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(move || {
                        AuthenticationManager::in_memory_authentication()
                            .password_encoder(enc.clone())
                            .with_user(
                                User::with_encoded_password("admin", enc.encode("admin"))
                                    .roles(&["ADMIN".into(), "USER".into()])
                                    .authorities(&["posts:write".into()])
                            )
                    })
                    .config_authorizer(|| {
                        AuthorizationManager::request_matcher()
                            .http_basic()
                    })
            )
            .service(admin)
            .service(create_post)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Security Macros

| Macro | Spring Equivalent | Description |
|-------|------------------|-------------|
| `#[secured("ADMIN")]` | `@Secured("ROLE_ADMIN")` | Role-based access |
| `#[pre_authorize("...")]` | `@PreAuthorize("...")` | Expression-based access |
| `#[permit_all]` | `@PermitAll` | Public access |
| `#[deny_all]` | `@DenyAll` | Deny all access |
| `#[roles_allowed("ADMIN")]` | `@RolesAllowed("ADMIN")` | Java EE style |

## Expression Language

```rust
// Role checks
#[pre_authorize("hasRole('ADMIN')")]
#[pre_authorize("hasAnyRole('ADMIN', 'MANAGER')")]

// Authority checks
#[pre_authorize("hasAuthority('users:write')")]
#[pre_authorize("hasAnyAuthority('read', 'write')")]

// Logical operators
#[pre_authorize("hasRole('ADMIN') OR hasAuthority('users:manage')")]
#[pre_authorize("hasRole('USER') AND hasAuthority('premium')")]
#[pre_authorize("NOT hasRole('GUEST')")]

// Complex expressions
#[pre_authorize("hasRole('ADMIN') OR (hasRole('USER') AND hasAuthority('posts:write'))")]
```

## URL-Based Authorization

```rust
use actix_security::http::security::{AuthorizationManager, Access, AntMatcher};

AuthorizationManager::request_matcher()
    .login_url("/login")
    .http_basic()
    .add_matcher("/admin/.*", Access::new().roles(vec!["ADMIN"]))
    .add_matcher("/api/.*", Access::new().authenticated())
    .add_matcher("/user/.*", Access::new().roles(vec!["USER", "ADMIN"]))
```

## Rate Limiting

```rust
use actix_security::http::security::{RateLimiter, RateLimitConfig};
use std::time::Duration;

let rate_limiter = RateLimiter::new(
    RateLimitConfig::new()
        .requests_per_minute(60)
        .burst_size(10)
        .exclude_paths(vec!["/health", "/metrics"])
);

App::new()
    .wrap(rate_limiter)
```

## Account Locking

```rust
use actix_security::http::security::{AccountLockManager, LockConfig};
use std::time::Duration;

let lock_manager = AccountLockManager::new(
    LockConfig::new()
        .max_attempts(5)
        .lockout_duration(Duration::from_secs(15 * 60))
        .progressive_lockout(true)
);

// Check before login
let result = check_login(&lock_manager, &username).await;
if !result.is_allowed() {
    return HttpResponse::Forbidden().body("Account locked");
}

// Record failure
lock_manager.record_failure(&username).await;

// Record success (resets counter)
lock_manager.record_success(&username).await;
```

## Audit Logging

```rust
use actix_security::http::security::{AuditLogger, SecurityEvent, SecurityEventType, StdoutHandler};

let logger = AuditLogger::new()
    .add_handler(StdoutHandler::new());

// Log security events
logger.log_login_success(&username, &ip);
logger.log_login_failure(&username, &ip, "Invalid password");
logger.log(SecurityEvent::new(SecurityEventType::AccountLocked)
    .username(&username)
    .ip_address(&ip));
```

## Security Headers

```rust
use actix_security::http::security::SecurityHeaders;

App::new()
    .wrap(SecurityHeaders::default())  // Safe defaults
    // or
    .wrap(SecurityHeaders::strict())   // Maximum security
```

## Documentation

- **[User Guide](https://tbounsiar.github.io/actix-security/)** - Comprehensive documentation
- **[API Docs](https://docs.rs/actix-security)** - Detailed API reference
- **[Examples](./examples/)** - Working examples

### Documentation Chapters

- [Getting Started](./docs/src/getting-started/)
- [Authentication](./docs/src/authentication/)
- [Authorization](./docs/src/authorization/)
- [Security Macros](./docs/src/macros/)
- [Expression Language](./docs/src/expressions/)
- [Security Headers](./docs/src/features/security-headers.md)
- [Advanced Topics](./docs/src/advanced/)

## Examples

All examples are in the [`examples/`](./examples/) directory with individual README files.

```bash
# Run any example
cargo run -p actix-security-examples --bin <example_name>
```

| Example | Description | Features |
|---------|-------------|----------|
| [`basic_auth`](./examples/src/basic_auth/) | HTTP Basic authentication | `http-basic`, `argon2` |
| [`jwt_auth`](./examples/src/jwt_auth/) | JWT token authentication | `jwt` |
| [`session_auth`](./examples/src/session_auth/) | Session-based authentication | `session` |
| [`form_login`](./examples/src/form_login/) | Form-based login with CSRF | `form-login`, `csrf` |
| [`security_headers`](./examples/src/security_headers/) | Security HTTP headers | (core) |
| [`oidc_keycloak`](./examples/src/oidc_keycloak/) | OAuth2/OIDC with Keycloak | `oauth2` |
| [`security_complete`](./examples/src/security_complete/) | All features combined | `full` |

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `macros` | Yes | Procedural macros (`#[secured]`, `#[pre_authorize]`, etc.) |
| `argon2` | Yes | Argon2 password encoder |
| `http-basic` | Yes | HTTP Basic authentication |
| `bcrypt` | No | BCrypt password encoder |
| `jwt` | No | JWT authentication (HS256, RS256, ES256) |
| `session` | No | Session-based authentication |
| `form-login` | No | Form-based login |
| `csrf` | No | CSRF protection middleware |
| `remember-me` | No | Remember-me authentication |
| `oauth2` | No | OAuth2/OIDC authentication |
| `user-details` | No | Async UserDetailsService trait |
| `rate-limit` | No | Rate limiting middleware |
| `audit` | No | Security event logging |
| `account-lock` | No | Account locking after failed attempts |
| `ldap` | No | LDAP/Active Directory authentication |
| `saml` | No | SAML 2.0 Single Sign-On |
| `full` | No | All features enabled |

## Crate Structure

| Crate | Description |
|-------|-------------|
| `actix-security` | Unified crate (recommended) - includes core + macros |
| `actix-security-core` | Core library with middleware, auth, and authorization |
| `actix-security-codegen` | Procedural macros for declarative security |

## Compatibility

| Actix Security | Actix Web | Rust |
|----------------|-----------|------|
| 0.2.x | 4.x | 1.70+ |

## Spring Security Comparison

Coming from Spring Security? See our [Migration Guide](./docs/src/reference/migration.md) and [Comparison Table](./docs/src/reference/spring-comparison.md).

### Feature Parity

| Spring Security | Actix Security | Status |
|-----------------|----------------|--------|
| `@Secured` | `#[secured]` | Complete |
| `@PreAuthorize` | `#[pre_authorize]` | Complete |
| `@PermitAll` / `@DenyAll` | `#[permit_all]` / `#[deny_all]` | Complete |
| HTTP Basic | `http-basic` feature | Complete |
| Form Login | `form-login` feature | Complete |
| Session Management | `session` feature | Complete |
| Remember-Me | `remember-me` feature | Complete |
| CSRF Protection | `csrf` feature | Complete |
| JWT (OAuth2 Resource Server) | `jwt` feature | Complete |
| OAuth2 Login | `oauth2` feature | Complete |
| LDAP Authentication | `ldap` feature | Complete |
| SAML 2.0 | `saml` feature | Complete |
| Password Encoding | `argon2`, `bcrypt` features | Complete |
| Security Headers | `SecurityHeaders` middleware | Complete |
| Method Security | Expression macros | Complete |
| URL-Based Security | `RequestMatcherAuthorizer` | Complete |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is dual-licensed under the MIT License and Apache License 2.0. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) for details.
