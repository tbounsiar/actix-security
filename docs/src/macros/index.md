# Security Macros Overview

Actix Security provides attribute macros for declarative method-level security, inspired by Spring Security and Java EE annotations.

## Available Macros

| Macro | Spring Equivalent | Java EE Equivalent | Description |
|-------|------------------|-------------------|-------------|
| `#[secured]` | `@Secured` | - | Role-based access |
| `#[pre_authorize]` | `@PreAuthorize` | - | Expression-based access |
| `#[permit_all]` | `@PermitAll` | `@PermitAll` | Public access |
| `#[deny_all]` | `@DenyAll` | `@DenyAll` | Block all access |
| `#[roles_allowed]` | `@Secured` | `@RolesAllowed` | Java EE style roles |

## Quick Reference

```rust
use actix_security::{secured, pre_authorize, permit_all, deny_all, roles_allowed};
use actix_security::http::security::AuthenticatedUser;

// Simple role check
#[secured("ADMIN")]
#[get("/admin")]
async fn admin(user: AuthenticatedUser) -> impl Responder { /* ... */ }

// Multiple roles (OR)
#[secured("ADMIN", "MANAGER")]
#[get("/management")]
async fn management(user: AuthenticatedUser) -> impl Responder { /* ... */ }

// Expression-based
#[pre_authorize("hasRole('USER') AND hasAuthority('posts:write')")]
#[post("/posts")]
async fn create_post(user: AuthenticatedUser) -> impl Responder { /* ... */ }

// Authority check
#[pre_authorize(authority = "users:delete")]
#[delete("/users/{id}")]
async fn delete_user(user: AuthenticatedUser) -> impl Responder { /* ... */ }

// Authenticated only
#[pre_authorize(authenticated)]
#[get("/profile")]
async fn profile(user: AuthenticatedUser) -> impl Responder { /* ... */ }

// Public endpoint
#[permit_all]
#[get("/health")]
async fn health() -> impl Responder { /* ... */ }

// Disabled endpoint
#[deny_all]
#[get("/deprecated")]
async fn deprecated(_user: AuthenticatedUser) -> impl Responder { /* ... */ }

// Java EE style
#[roles_allowed("ADMIN", "USER")]
#[get("/app")]
async fn app(user: AuthenticatedUser) -> impl Responder { /* ... */ }
```

## How They Work

Security macros wrap your handler with authorization checks at compile time. When a check fails, a `403 Forbidden` response is returned before your handler code executes.

### Before (your code)
```rust
#[secured("ADMIN")]
#[get("/admin")]
async fn admin(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Admin")
}
```

### After (macro expansion, simplified)
```rust
#[get("/admin")]
async fn admin(user: AuthenticatedUser) -> Result<impl Responder, AuthError> {
    // Injected security check
    if !user.has_any_role(&["ADMIN"]) {
        return Err(AuthError::Forbidden);
    }

    // Your original code
    Ok(HttpResponse::Ok().body("Admin"))
}
```

## Macro Placement

**Important**: Security macros must be placed **before** the route macro:

```rust
// ✓ Correct
#[secured("ADMIN")]
#[get("/admin")]
async fn admin() -> impl Responder { /* ... */ }

// ✗ Wrong - security check won't be applied
#[get("/admin")]
#[secured("ADMIN")]
async fn admin() -> impl Responder { /* ... */ }
```

## Compile-Time Expression Parsing

For `#[pre_authorize]` with expressions, parsing and validation happens at compile time:

```rust
// This is validated at compile time
#[pre_authorize("hasRole('ADMIN') OR hasAuthority('users:write')")]
#[get("/users")]
async fn users(user: AuthenticatedUser) -> impl Responder { /* ... */ }

// This would cause a compile error
#[pre_authorize("invalid expression !!!")]  // Compile error
#[get("/users")]
async fn users(user: AuthenticatedUser) -> impl Responder { /* ... */ }
```

Benefits:
- **Zero runtime overhead** - No expression parsing at request time
- **Early error detection** - Invalid expressions fail at compile time
- **Type safety** - Rust's type system ensures correctness

## Sections

- [@secured](./secured.md) - Simple role-based security
- [@pre_authorize](./pre-authorize.md) - Expression-based security
- [@permit_all](./permit-all.md) - Public endpoints
- [@deny_all](./deny-all.md) - Blocked endpoints
- [@roles_allowed](./roles-allowed.md) - Java EE style
