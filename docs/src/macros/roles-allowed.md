# @roles_allowed

Java EE-style role-based security. Functionally equivalent to `#[secured]`.

## Syntax

```rust
#[roles_allowed("ROLE")]           // Single role
#[roles_allowed("ROLE1", "ROLE2")] // Multiple roles (OR logic)
```

## Usage

```rust
use actix_web::{get, HttpResponse, Responder};
use actix_security::roles_allowed;
use actix_security::http::security::AuthenticatedUser;

// Single role
#[roles_allowed("ADMIN")]
#[get("/admin")]
async fn admin_panel(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Admin Panel")
}

// Multiple roles
#[roles_allowed("ADMIN", "MANAGER")]
#[get("/management")]
async fn management(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Management")
}
```

## Java EE Equivalent

This macro follows the Java EE `@RolesAllowed` annotation:

**Java EE:**
```java
@RolesAllowed("ADMIN")
@GET
@Path("/admin")
public String admin() {
    return "admin";
}

@RolesAllowed({"ADMIN", "MANAGER"})
@GET
@Path("/management")
public String management() {
    return "management";
}
```

**Actix Security:**
```rust
#[roles_allowed("ADMIN")]
#[get("/admin")]
async fn admin(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("admin")
}

#[roles_allowed("ADMIN", "MANAGER")]
#[get("/management")]
async fn management(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("management")
}
```

## Comparison with @secured

`#[roles_allowed]` and `#[secured]` are functionally identical. Choose based on your preferred naming convention:

| If you're coming from... | Use |
|--------------------------|-----|
| Spring Security | `#[secured]` |
| Java EE / Jakarta EE | `#[roles_allowed]` |

```rust
// These are equivalent:

#[roles_allowed("ADMIN")]
#[get("/admin")]
async fn admin_v1(user: AuthenticatedUser) -> impl Responder { /* ... */ }

#[secured("ADMIN")]
#[get("/admin")]
async fn admin_v2(user: AuthenticatedUser) -> impl Responder { /* ... */ }
```

## OR Logic

Like `#[secured]`, multiple roles use OR logic:

```rust
#[roles_allowed("ADMIN", "MANAGER", "SUPERVISOR")]
#[get("/reports")]
async fn reports(user: AuthenticatedUser) -> impl Responder {
    // Access granted if user has ADMIN OR MANAGER OR SUPERVISOR
    HttpResponse::Ok().body("Reports")
}
```

For AND logic, use `#[pre_authorize]`:

```rust
#[pre_authorize("hasRole('ADMIN') AND hasRole('AUDITOR')")]
#[get("/audit")]
async fn audit(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Audit")
}
```

## Examples

### Admin Dashboard

```rust
#[roles_allowed("ADMIN")]
#[get("/admin/dashboard")]
async fn admin_dashboard(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Welcome, Admin {}!", user.get_username()))
}
```

### Multi-Tier Access

```rust
// Executive + Management access
#[roles_allowed("EXECUTIVE", "MANAGER")]
#[get("/reports/financial")]
async fn financial_reports(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Financial Reports")
}

// All staff access
#[roles_allowed("EXECUTIVE", "MANAGER", "EMPLOYEE")]
#[get("/reports/general")]
async fn general_reports(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("General Reports")
}
```

### Service Account

```rust
#[roles_allowed("SERVICE", "ADMIN")]
#[post("/internal/sync")]
async fn internal_sync(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Synchronized")
}
```

## How It Works

`#[roles_allowed]` delegates to `#[secured]` internally:

```rust
// Input
#[roles_allowed("ADMIN", "MANAGER")]
#[get("/management")]
async fn management(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Management")
}

// Effectively same as
#[secured("ADMIN", "MANAGER")]
#[get("/management")]
async fn management(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Management")
}

// Which expands to (simplified)
#[get("/management")]
async fn management(user: AuthenticatedUser) -> Result<impl Responder, AuthError> {
    if !user.has_any_role(&["ADMIN".to_string(), "MANAGER".to_string()]) {
        return Err(AuthError::Forbidden);
    }
    Ok(HttpResponse::Ok().body("Management"))
}
```

## When to Use

Use `#[roles_allowed]` when:
- You prefer Java EE naming conventions
- You're porting code from Java EE
- Your team is familiar with `@RolesAllowed`

Use `#[secured]` instead when:
- You prefer Spring Security naming conventions
- Your team is familiar with `@Secured`

Use `#[pre_authorize]` instead when:
- You need authority checks (not just roles)
- You need complex AND/OR/NOT logic
- You need expression-based security
