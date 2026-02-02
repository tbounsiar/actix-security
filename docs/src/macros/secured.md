# @secured

Simple role-based method security. Use when you need to check one or more roles.

## Syntax

```rust
#[secured("ROLE")]           // Single role
#[secured("ROLE1", "ROLE2")] // Multiple roles (OR logic)
```

## Basic Usage

```rust
use actix_web::{get, HttpResponse, Responder};
use actix_security::secured;
use actix_security::http::security::AuthenticatedUser;

// Single role
#[secured("ADMIN")]
#[get("/admin/dashboard")]
async fn admin_dashboard(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Welcome Admin: {}", user.get_username()))
}

// Multiple roles - user needs ANY of the specified roles
#[secured("ADMIN", "MANAGER", "SUPERVISOR")]
#[get("/reports")]
async fn view_reports(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Reports")
}
```

## OR Logic

When multiple roles are specified, the user needs **at least one** matching role:

```rust
#[secured("ADMIN", "MANAGER")]
```

This grants access if the user has `ADMIN` OR `MANAGER` role.

For AND logic, use `#[pre_authorize]`:

```rust
#[pre_authorize("hasRole('ADMIN') AND hasRole('MANAGER')")]
```

## Handler Requirements

The handler **must** have an `AuthenticatedUser` parameter:

```rust
// ✓ Correct
#[secured("USER")]
#[get("/profile")]
async fn profile(user: AuthenticatedUser) -> impl Responder { /* ... */ }

// ✗ Wrong - missing AuthenticatedUser
#[secured("USER")]
#[get("/profile")]
async fn profile() -> impl Responder { /* ... */ }
```

The `AuthenticatedUser` provides access to user information:

```rust
#[secured("USER")]
#[get("/profile")]
async fn profile(user: AuthenticatedUser) -> impl Responder {
    let username = user.get_username();
    let roles = user.get_roles();
    let authorities = user.get_authorities();

    HttpResponse::Ok().body(format!(
        "User: {}\nRoles: {:?}\nAuthorities: {:?}",
        username, roles, authorities
    ))
}
```

## Examples

### Admin-Only Endpoint

```rust
#[secured("ADMIN")]
#[get("/admin/users")]
async fn list_all_users(user: AuthenticatedUser) -> impl Responder {
    // Only ADMIN can access
    HttpResponse::Ok().json(get_all_users())
}
```

### Premium Content

```rust
#[secured("PREMIUM", "ADMIN")]
#[get("/premium/content")]
async fn premium_content(user: AuthenticatedUser) -> impl Responder {
    // PREMIUM users and ADMINs can access
    HttpResponse::Ok().body("Exclusive content")
}
```

### Service Account

```rust
#[secured("SERVICE")]
#[post("/internal/sync")]
async fn internal_sync(user: AuthenticatedUser) -> impl Responder {
    // Only SERVICE accounts can call this
    HttpResponse::Ok().body("Synced")
}
```

## Error Response

When access is denied, a `403 Forbidden` response is returned:

```
HTTP/1.1 403 Forbidden
Content-Length: 0
```

## How It Works

The macro expands to:

```rust
// Input
#[secured("ADMIN")]
#[get("/admin")]
async fn admin(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Admin")
}

// Expansion (simplified)
#[get("/admin")]
async fn admin(user: AuthenticatedUser) -> Result<impl Responder, AuthError> {
    if !user.has_any_role(&["ADMIN".to_string()]) {
        return Err(AuthError::Forbidden);
    }
    Ok(HttpResponse::Ok().body("Admin"))
}
```

## Spring Security Comparison

**Spring Security:**
```java
@Secured("ROLE_ADMIN")
@GetMapping("/admin")
public String admin() {
    return "admin";
}

@Secured({"ROLE_ADMIN", "ROLE_MANAGER"})
@GetMapping("/management")
public String management() {
    return "management";
}
```

**Actix Security:**
```rust
#[secured("ADMIN")]
#[get("/admin")]
async fn admin(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("admin")
}

#[secured("ADMIN", "MANAGER")]
#[get("/management")]
async fn management(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("management")
}
```

> **Note**: Unlike Spring Security, Actix Security doesn't add a `ROLE_` prefix. Roles are used exactly as specified.

## When to Use

Use `#[secured]` when:
- You need simple role checks
- OR logic is sufficient
- You don't need expressions

Use `#[pre_authorize]` instead when:
- You need authority checks
- You need AND logic
- You need complex expressions
