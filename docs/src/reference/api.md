# API Documentation

Links to the detailed API documentation for each crate.

## Crate Documentation

### actix-security

Main library providing security middleware, authentication, and authorization.

**[View API Docs](https://docs.rs/actix-security)** (when published)

Generate locally:
```bash
cargo doc -p actix-security --open
```

#### Key Types

| Type | Description |
|------|-------------|
| `SecurityTransform` | Main middleware |
| `Authenticator` | Authentication trait |
| `Authorizer` | Authorization trait |
| `User` | User model |
| `AuthenticatedUser` | Request extractor |
| `SecurityContext` | Current user access |
| `SecurityHeaders` | Security headers middleware |
| `PasswordEncoder` | Password encoding trait |
| `ExpressionRoot` | Custom expression trait |
| `JwtAuthenticator` | JWT authentication (feature: `jwt`) |
| `JwtConfig` | JWT configuration (feature: `jwt`) |
| `SessionAuthenticator` | Session authentication (feature: `session`) |
| `SessionConfig` | Session configuration (feature: `session`) |

### Procedural Macros

Procedural macros are included in `actix-security` when the `macros` feature is enabled (default).

> For the underlying implementation, see the `actix-security-codegen` crate.

#### Macros

| Macro | Description |
|-------|-------------|
| `#[secured]` | Role-based access |
| `#[pre_authorize]` | Expression-based access |
| `#[permit_all]` | Public endpoints |
| `#[deny_all]` | Blocked endpoints |
| `#[roles_allowed]` | Java EE style |

## Module Reference

### actix_security::http::security

Main security module.

```rust
use actix_security::http::security::{
    // Traits
    Authenticator,
    Authorizer,
    PasswordEncoder,

    // Types
    User,
    AuthenticatedUser,
    OptionalUser,
    SecurityContext,
    SecurityHeaders,

    // Implementations
    MemoryAuthenticator,
    RequestMatcherAuthorizer,
    Access,
    Argon2PasswordEncoder,
    NoOpPasswordEncoder,
    DelegatingPasswordEncoder,

    // Factory methods
    AuthenticationManager,
    AuthorizationManager,
};
```

### actix_security::http::security::middleware

Middleware types.

```rust
use actix_security::http::security::middleware::SecurityTransform;
```

### actix_security::http::security::expression

Expression language types.

```rust
use actix_security::http::security::expression::{
    Expression,
    BinaryOp,
    UnaryOp,
    ExpressionEvaluator,
    ExpressionRoot,
    DefaultExpressionRoot,
    SecurityExpression,
    ParseError,
};
```

### actix_security::http::security::jwt

JWT authentication types (feature: `jwt`).

```rust
use actix_security::http::security::jwt::{
    JwtAuthenticator,
    JwtConfig,
    JwtTokenService,
    Claims,
    JwtError,
    Algorithm,
};
```

### actix_security::http::security::session

Session authentication types (feature: `session`).

```rust
use actix_security::http::security::session::{
    SessionAuthenticator,
    SessionConfig,
    SessionUser,
    SessionLoginService,
    SessionError,
};
```

### actix_security::http::security::headers

Security headers types.

```rust
use actix_security::http::security::headers::{
    SecurityHeaders,
    FrameOptions,
    ReferrerPolicy,
};
```

### actix_security::http::error

Error types.

```rust
use actix_security::http::error::AuthError;
```

## Quick Reference

### Creating Users

```rust
// With encoded password
User::with_encoded_password("username", encoder.encode("password"))
    .roles(&["ROLE".into()])
    .authorities(&["auth".into()])

// Plain (for testing only)
User::new("username".to_string(), "password".to_string())
    .roles(&["ROLE".into()])
```

### Configuring Authentication

```rust
AuthenticationManager::in_memory_authentication()
    .password_encoder(encoder)
    .with_user(user)
```

### Configuring Authorization

```rust
AuthorizationManager::request_matcher()
    .login_url("/login")
    .http_basic()
    .add_matcher("/admin/.*", Access::new().roles(vec!["ADMIN"]))
    .add_matcher("/api/.*", Access::new().authenticated())
```

### Access Configuration

```rust
Access::new()
    .roles(vec!["ROLE1", "ROLE2"])
    .authorities(vec!["auth1", "auth2"])
    .authenticated()
    .deny_all()
```

### Security Headers

```rust
SecurityHeaders::new()
    .frame_options(FrameOptions::Deny)
    .content_security_policy("default-src 'self'")
    .hsts(true, 31536000)
    .referrer_policy(ReferrerPolicy::NoReferrer)

SecurityHeaders::default()  // Safe defaults
SecurityHeaders::strict()   // Maximum security
```

### Password Encoding

```rust
let encoder = Argon2PasswordEncoder::new();
let encoded = encoder.encode("password");
let matches = encoder.matches("password", &encoded);
```

### Security Context

```rust
SecurityContext::get_user()        // Option<User>
SecurityContext::has_role("ROLE")  // bool
SecurityContext::has_authority("auth")  // bool
SecurityContext::is_authenticated()     // bool
```

## Feature Flags

### actix-security

| Feature | Default | Description |
|---------|---------|-------------|
| `argon2` | Yes | Argon2 password encoder |
| `http-basic` | Yes | HTTP Basic authentication |
| `jwt` | No | JWT authentication |
| `session` | No | Session-based authentication |
| `full` | No | All features enabled |

```toml
# Default features (argon2, http-basic)
actix-security = "0.2"

# Minimal
actix-security = { version = "0.2", default-features = false }

# With JWT
actix-security = { version = "0.2", features = ["jwt"] }

# With Session
actix-security = { version = "0.2", features = ["session"] }

# All features
actix-security = { version = "0.2", features = ["full"] }
```
