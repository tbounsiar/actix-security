# Authorization

Authorization determines **what** an authenticated user can do. Actix Security provides two complementary approaches:

1. **URL-Based Authorization** - Configure access rules for URL patterns
2. **Method Security** - Protect individual handlers with attribute macros

## Core Concepts

### The Authorizer Trait

```rust
pub trait Authorizer: Clone + Send + Sync + 'static {
    /// Check if the user can access the requested resource.
    fn authorize(&self, user: Option<&User>, req: &ServiceRequest) -> AuthorizationResult;
}

pub enum AuthorizationResult {
    Granted,           // Access allowed
    Denied,            // 403 Forbidden
    LoginRequired,     // 401 Unauthorized / redirect to login
}
```

### Roles vs Authorities

Both are permission types, but serve different purposes:

| Concept | Purpose | Example |
|---------|---------|---------|
| **Roles** | Coarse-grained access | `ADMIN`, `USER`, `GUEST` |
| **Authorities** | Fine-grained permissions | `users:read`, `posts:write` |

See [Roles vs Authorities](./roles-authorities.md) for detailed guidance.

## URL-Based Authorization

Configure access rules by URL pattern:

```rust
use actix_security::http::security::{AuthorizationManager, Access};

let authorizer = AuthorizationManager::request_matcher()
    .login_url("/login")
    .http_basic()
    // Admin section
    .add_matcher("/admin/.*", Access::new().roles(vec!["ADMIN"]))
    // API requires authentication
    .add_matcher("/api/.*", Access::new().authenticated())
    // User section
    .add_matcher("/user/.*", Access::new().roles(vec!["USER", "ADMIN"]))
    // Everything else is public
```

## Method Security

Protect individual handlers with macros:

```rust
use actix_security::{secured, pre_authorize};

// Simple role check
#[secured("ADMIN")]
#[get("/admin/users")]
async fn list_users(user: AuthenticatedUser) -> impl Responder { /* ... */ }

// Expression-based
#[pre_authorize("hasRole('USER') AND hasAuthority('posts:write')")]
#[post("/posts")]
async fn create_post(user: AuthenticatedUser) -> impl Responder { /* ... */ }
```

## Authorization Flow

```
Request → Authenticator → Authorizer
                              ↓
                    ┌─────────────────────┐
                    │ URL Pattern Match?  │
                    └─────────┬───────────┘
                              │
           ┌──────────────────┼──────────────────┐
           ↓                  ↓                  ↓
      [Matched]          [No Match]          [Public]
           ↓                  ↓                  ↓
    Check roles/auth    Continue to       Allow request
           ↓             handler
    ┌──────┴──────┐
    ↓             ↓
[Granted]    [Denied]
    ↓             ↓
Handler      403 Forbidden
    ↓
Method security
(if applicable)
```

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| `authorizeHttpRequests()` | `RequestMatcherAuthorizer` |
| `hasRole("ADMIN")` | `.roles(vec!["ADMIN"])` |
| `hasAuthority("read")` | `.authorities(vec!["read"])` |
| `authenticated()` | `.authenticated()` |
| `permitAll()` | No matcher (default allow) |
| `denyAll()` | `Access::new().deny_all()` |
| `@PreAuthorize` | `#[pre_authorize]` |
| `@Secured` | `#[secured]` |

## Sections

- [URL-Based Authorization](./url-based.md) - Configure access by URL pattern
- [Method Security](./method-security.md) - Protect handlers with macros
- [Roles vs Authorities](./roles-authorities.md) - When to use each
- [Custom Authorizers](./custom.md) - Build your own
