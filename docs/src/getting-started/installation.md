# Installation

## Cargo Dependencies

Add the following to your `Cargo.toml`:

```toml
[dependencies]
actix-security = "0.2"
```

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `macros` | ✓ | Procedural macros (`#[secured]`, `#[pre_authorize]`, etc.) |
| `argon2` | ✓ | Enables Argon2 password encoding |
| `http-basic` | ✓ | Enables HTTP Basic authentication |
| `jwt` | | Enables JWT authentication |
| `session` | | Enables Session-based authentication |
| `oauth2` | | Enables OAuth2/OIDC authentication |
| `full` | | All features enabled |

### Minimal Installation

For a minimal installation without optional features:

```toml
[dependencies]
actix-security = { version = "0.2", default-features = false }
```

### Full Installation

For all features:

```toml
[dependencies]
actix-security = { version = "0.2", features = ["full"] }
```

## Compatibility

| Actix Security | Actix Web | Rust |
|----------------|-----------|------|
| 0.1.x | 4.x | 1.70+ |

## Crate Overview

The `actix-security` crate provides:

**Core Features:**
- Security middleware (`SecurityTransform`)
- Authentication (`MemoryAuthenticator`, `Authenticator` trait)
- Authorization (`RequestMatcherAuthorizer`, `Authorizer` trait)
- Password encoding (`Argon2PasswordEncoder`, `DelegatingPasswordEncoder`)
- User model (`User`, `AuthenticatedUser`)
- Security headers middleware (`SecurityHeaders`)
- Security context (`SecurityContext`)
- Expression evaluation

**Procedural Macros (with `macros` feature):**
- `#[secured]` - Role-based method security
- `#[pre_authorize]` - Expression-based method security
- `#[permit_all]` - Mark endpoints as public
- `#[deny_all]` - Block all access
- `#[roles_allowed]` - Java EE style role checks

## Verifying Installation

Create a simple test to verify everything is working:

```rust
use actix_security::http::security::{
    AuthenticationManager, Argon2PasswordEncoder, PasswordEncoder, User
};
use actix_security::secured;

#[test]
fn test_installation() {
    // Test password encoding
    let encoder = Argon2PasswordEncoder::new();
    let encoded = encoder.encode("test");
    assert!(encoder.matches("test", &encoded));

    // Test user creation
    let user = User::with_encoded_password("test", encoded)
        .roles(&["USER".into()]);
    assert_eq!(user.username, "test");
    assert!(user.roles.contains(&"USER".into()));
}
```

Run with:

```bash
cargo test test_installation
```
