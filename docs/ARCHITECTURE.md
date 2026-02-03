# Actix Security - Architecture

This document describes the architecture of actix-security and how it maps to Spring Security concepts.

## Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Actix Web Application                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────┐  │
│  │  SecurityTransform│───▶│  SecurityService │───▶│   Handler    │  │
│  │   (Middleware)    │    │                  │    │              │  │
│  └──────────────────┘    └────────┬─────────┘    └──────────────┘  │
│                                   │                                  │
│                    ┌──────────────┴──────────────┐                  │
│                    │                             │                  │
│              ┌─────▼─────┐              ┌────────▼────────┐        │
│              │Authenticator│              │   Authorizer   │        │
│              │  (trait)   │              │    (trait)     │        │
│              └─────┬─────┘              └────────┬────────┘        │
│                    │                             │                  │
│         ┌─────────┴─────────┐         ┌─────────┴─────────┐       │
│         │                   │         │                   │       │
│  ┌──────▼──────┐  ┌────────▼───┐  ┌──▼─────────────┐ ┌───▼───┐  │
│  │   Memory    │  │   JDBC     │  │RequestMatcher  │ │ ACL   │  │
│  │Authenticator│  │Authenticator│  │  Authorizer    │ │       │  │
│  └─────────────┘  └────────────┘  └────────────────┘ └───────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Spring Security Mapping

### Core Components

| Actix Security | Spring Security | Purpose |
|----------------|-----------------|---------|
| `SecurityTransform` | `SecurityFilterChain` | Middleware factory |
| `SecurityService` | `FilterChainProxy` | Request processing |
| `Authenticator` trait | `AuthenticationProvider` | User extraction |
| `Authorizer` trait | `AccessDecisionManager` | Access decisions |
| `User` | `UserDetails` | User representation |
| `PasswordEncoder` trait | `PasswordEncoder` | Password hashing |
| `Argon2PasswordEncoder` | `Argon2PasswordEncoder` | Argon2 hashing |
| `HttpBasicConfig` | `HttpBasicConfigurer` | HTTP Basic auth |
| `AuthError` | `AuthenticationException` | Security errors |
| `#[secured]` | `@Secured` | Role-based macro |
| `#[pre_authorize]` | `@PreAuthorize` | Expression-based macro |

### Authentication Flow

```
Request
   │
   ▼
┌─────────────────────────────────────────┐
│  SecurityService::call()                │
│  ┌───────────────────────────────────┐  │
│  │ Check Authorization Header        │  │  ◀── "Basic base64(user:pass)"
│  └─────────────────┬─────────────────┘  │
│                    │                    │
│                    ▼                    │
│  ┌───────────────────────────────────┐  │
│  │ Decode Base64, extract user:pass │  │  ◀── HTTP Basic Auth (RFC 7617)
│  └─────────────────┬─────────────────┘  │
│                    │                    │
│                    ▼                    │
│  ┌───────────────────────────────────┐  │
│  │ authenticator.get_user()          │  │  ◀── Lookup user in store
│  └─────────────────┬─────────────────┘  │
│                    │                    │
│                    ▼                    │
│  ┌───────────────────────────────────┐  │
│  │ PasswordEncoder.matches()         │  │  ◀── Verify with Argon2
│  └─────────────────┬─────────────────┘  │
│                    │                    │
│        ┌───────────┴───────────┐        │
│        │                       │        │
│        ▼                       ▼        │
│   Some(User)                 None       │
│        │                       │        │
│        ▼                       ▼        │
│   Continue to              401 with     │
│   Authorizer          WWW-Authenticate  │
│                                         │
└─────────────────────────────────────────┘
```

### Authorization Flow

```
User + Request
       │
       ▼
┌──────────────────────────────────────┐
│  Authorizer::process()               │
│  ┌────────────────────────────────┐  │
│  │ Match request path to rules    │  │
│  └───────────────┬────────────────┘  │
│                  │                   │
│          ┌───────┴───────┐           │
│          │               │           │
│          ▼               ▼           │
│     Match found     No match         │
│          │               │           │
│          ▼               ▼           │
│  ┌───────────────┐  ┌────────────┐   │
│  │Check roles/   │  │ Forward to │   │
│  │authorities    │  │ Handler    │   │
│  └───────┬───────┘  │ (may use   │   │
│          │          │ macros)    │   │
│    ┌─────┴─────┐    └────────────┘   │
│    │           │                     │
│    ▼           ▼                     │
│  Allowed    Denied                   │
│    │           │                     │
│    ▼           ▼                     │
│  Call       403                      │
│  Handler    Forbidden                │
│                                      │
└──────────────────────────────────────┘
```

## Module Structure

```
actix-security/
├── core/                          # actix-security-core
│   └── src/
│       ├── lib.rs                 # Crate root
│       └── http/
│           ├── mod.rs
│           ├── auth/              # Access models
│           │   ├── mod.rs
│           │   └── access.rs      # Access struct (roles/authorities)
│           ├── error/             # Error types
│           │   ├── mod.rs
│           │   └── auth_error.rs  # AuthError enum
│           └── security/          # Core security
│               ├── mod.rs
│               ├── config.rs      # Traits: Authenticator, Authorizer
│               ├── crypto.rs      # PasswordEncoder, Argon2PasswordEncoder
│               ├── user.rs        # User model
│               ├── manager.rs     # Factory methods
│               ├── middleware.rs  # SecurityTransform, SecurityService
│               ├── extractors.rs  # AuthenticatedUser, OptionalUser
│               └── web.rs         # MemoryAuthenticator, RequestMatcherAuthorizer
│
├── codegen/                       # actix-security-codegen
│   └── src/
│       └── lib.rs                 # #[secured], #[pre_authorize] macros
│
└── test/                          # actix-security-test
    ├── src/
    │   └── main.rs                # Example application
    └── tests/
        └── integration_tests.rs   # 25+ integration tests
```

## Trait Definitions

### Authenticator

```rust
/// Extracts user identity from an HTTP request.
///
/// # Spring Equivalent
/// `AuthenticationProvider` / `UserDetailsService`
///
/// # Implementations
/// - `MemoryAuthenticator`: In-memory user store with HTTP Basic Auth
/// - Future: `JdbcAuthenticator`, `LdapAuthenticator`, `JwtAuthenticator`
pub trait Authenticator {
    fn get_user(&self, req: &ServiceRequest) -> Option<User>;
}
```

### Authorizer

```rust
/// Decides whether an authenticated user can access a resource.
///
/// # Spring Equivalent
/// `AccessDecisionManager` / `AuthorizationManager`
///
/// # Implementations
/// - `RequestMatcherAuthorizer`: URL pattern-based authorization
/// - Future: `MethodSecurityAuthorizer`, `AclAuthorizer`
pub trait Authorizer<B> {
    fn process(
        &self,
        req: ServiceRequest,
        user: Option<&User>,
        next: impl FnOnce(ServiceRequest) -> LocalBoxFuture<'static, Result<ServiceResponse<B>, Error>>
    ) -> LocalBoxFuture<'static, Result<ServiceResponse<EitherBody<B>>, Error>>;
}
```

### PasswordEncoder

```rust
/// Encodes and verifies passwords.
///
/// # Spring Equivalent
/// `org.springframework.security.crypto.password.PasswordEncoder`
///
/// # Implementations
/// - `Argon2PasswordEncoder`: Recommended for production
/// - `DelegatingPasswordEncoder`: Multi-format support
/// - `NoOpPasswordEncoder`: Plain text (dev only!)
pub trait PasswordEncoder: Send + Sync {
    /// Encodes a raw password.
    fn encode(&self, raw_password: &str) -> String;

    /// Verifies a raw password against an encoded one.
    fn matches(&self, raw_password: &str, encoded_password: &str) -> bool;

    /// Whether the encoded password should be upgraded.
    fn upgrade_encoding(&self, _encoded_password: &str) -> bool { false }
}
```

## Configuration Pattern

### Current (Builder Pattern)

```rust
use actix_security::http::security::{
    AuthenticationManager, AuthorizationManager,
    Argon2PasswordEncoder, PasswordEncoder, User,
};
use actix_security::http::security::web::Access;
use actix_security::http::security::middleware::SecurityTransform;

// Create password encoder
let encoder = Argon2PasswordEncoder::new();

// Configure authentication
let authenticator = AuthenticationManager::in_memory_authentication()
    .password_encoder(encoder.clone())
    .with_user(
        User::with_encoded_password("admin", encoder.encode("secret"))
            .roles(&["ADMIN".into(), "USER".into()])
            .authorities(&["users:read".into(), "users:write".into()])
    );

// Configure authorization
let authorizer = AuthorizationManager::request_matcher()
    .login_url("/login")
    .http_basic()
    .add_matcher("/admin/.*", Access::new().roles(vec!["ADMIN"]))
    .add_matcher("/api/.*", Access::new().authorities(vec!["users:read"]));

// Apply to app
App::new().service(
    web::scope("")
        .wrap(
            SecurityTransform::new()
                .config_authenticator(|| authenticator)
                .config_authorizer(|| authorizer)
        )
        .service(my_handler)
)
```

### Target (Spring-like DSL)

```rust
HttpSecurity::new()
    .authorize_requests(|auth| {
        auth.ant_matchers("/admin/**").has_role("ADMIN")
            .ant_matchers("/user/**").has_any_role(&["ADMIN", "USER"])
            .any_request().authenticated()
    })
    .http_basic(|basic| {
        basic.realm("MyApplication")
    })
    .form_login(|form| {
        form.login_page("/login")
            .login_processing_url("/login")
            .default_success_url("/")
            .failure_url("/login?error")
    })
    .logout(|logout| {
        logout.logout_url("/logout")
              .logout_success_url("/login?logout")
    })
    .build()
```

## Macro System

### `#[secured("ROLE1", "ROLE2")]`

Spring equivalent: `@Secured({"ROLE_ADMIN", "ROLE_USER"})`

```rust
// Input
#[secured("ADMIN")]
#[get("/admin")]
async fn admin_only(user: AuthenticatedUser) -> impl Responder { }

// Expands to (conceptually)
#[get("/admin")]
async fn admin_only(user: AuthenticatedUser) -> Result<impl Responder, AuthError> {
    if !user.has_any_role(&["ADMIN"]) {
        return Err(AuthError::Forbidden);
    }
    // original function body
}
```

### `#[pre_authorize(...)]`

Spring equivalent: `@PreAuthorize("...")`

| Actix Security | Spring Security |
|----------------|-----------------|
| `#[pre_authorize(authenticated)]` | `@PreAuthorize("isAuthenticated()")` |
| `#[pre_authorize(role = "ADMIN")]` | `@PreAuthorize("hasRole('ADMIN')")` |
| `#[pre_authorize(roles = ["A", "B"])]` | `@PreAuthorize("hasAnyRole('A', 'B')")` |
| `#[pre_authorize(authority = "read")]` | `@PreAuthorize("hasAuthority('read')")` |
| `#[pre_authorize(authorities = ["r", "w"])]` | `@PreAuthorize("hasAnyAuthority('r', 'w')")` |

```rust
// Input
#[pre_authorize(authority = "users:write")]
#[post("/users")]
async fn create_user(user: AuthenticatedUser) -> impl Responder { }

// Expands to (conceptually)
#[post("/users")]
async fn create_user(user: AuthenticatedUser) -> Result<impl Responder, AuthError> {
    if !user.has_authority("users:write") {
        return Err(AuthError::Forbidden);
    }
    // original function body
}
```

## Error Handling

```rust
pub enum AuthError {
    /// 401 Unauthorized - Authentication required
    Unauthorized,

    /// 403 Forbidden - Authenticated but not authorized
    Forbidden,

    /// 401 with specific message - Invalid credentials
    BadCredentials(String),

    /// 401 - Token expired or invalid
    TokenError,

    /// 423 Locked - Account locked
    AccountLocked,

    /// 401 - Account disabled
    AccountDisabled,
}
```

## Thread Safety

The middleware uses `Rc<S>` for the inner service, which is appropriate for Actix Web's single-threaded-per-core model. For shared state across requests (like user stores), use:

- `web::Data<T>` for read-heavy shared state
- `web::Data<Mutex<T>>` for mutable shared state
- External storage (Redis, database) for distributed state

## Testing

The library includes comprehensive integration tests in `test/tests/integration_tests.rs`:

| Test Category | Count | Description |
|---------------|-------|-------------|
| HTTP Basic Auth | 5 | Success, wrong password, unknown user, no auth, login page |
| Middleware Authorization | 6 | Admin routes, user routes, API authorities |
| `#[secured]` Macro | 4 | Role checks, multiple roles |
| `#[pre_authorize]` Macro | 8 | Authority, authorities array, role, authenticated |
| Password Encoder | 2 | Encode/verify, salt uniqueness |

Run tests with:
```bash
cargo test
```
