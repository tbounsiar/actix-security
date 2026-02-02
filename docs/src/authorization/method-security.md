# Method Security

Protect individual handlers with attribute macros for fine-grained access control.

## Overview

Method security complements URL-based authorization by adding checks directly to handlers. This is useful when:

- Different endpoints at similar URLs need different permissions
- You want self-documenting security rules
- Complex authorization logic is needed

## Available Macros

| Macro | Spring Equivalent | Use Case |
|-------|------------------|----------|
| `#[secured("ROLE")]` | `@Secured` | Simple role check |
| `#[pre_authorize(...)]` | `@PreAuthorize` | Expression-based access |
| `#[permit_all]` | `@PermitAll` | Explicitly public |
| `#[deny_all]` | `@DenyAll` | Block all access |
| `#[roles_allowed("ROLE")]` | `@RolesAllowed` | Java EE style |

## @secured

Simple role-based access control:

```rust
use actix_security::secured;
use actix_security::http::security::AuthenticatedUser;

// Single role
#[secured("ADMIN")]
#[get("/admin/users")]
async fn list_users(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("User list")
}

// Multiple roles (OR logic - any role grants access)
#[secured("ADMIN", "MANAGER")]
#[get("/reports")]
async fn view_reports(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Reports")
}
```

## @pre_authorize

Expression-based access control with full expression language support:

```rust
use actix_security::pre_authorize;

// Role check
#[pre_authorize(role = "ADMIN")]
#[get("/admin")]
async fn admin_only(user: AuthenticatedUser) -> impl Responder { /* ... */ }

// Authority check
#[pre_authorize(authority = "users:write")]
#[post("/users")]
async fn create_user(user: AuthenticatedUser) -> impl Responder { /* ... */ }

// Multiple authorities (OR logic)
#[pre_authorize(authorities = ["users:read", "users:write"])]
#[get("/users")]
async fn list_users(user: AuthenticatedUser) -> impl Responder { /* ... */ }

// Authenticated only
#[pre_authorize(authenticated)]
#[get("/profile")]
async fn get_profile(user: AuthenticatedUser) -> impl Responder { /* ... */ }

// Full expression
#[pre_authorize("hasRole('USER') AND hasAuthority('posts:write')")]
#[post("/posts")]
async fn create_post(user: AuthenticatedUser) -> impl Responder { /* ... */ }
```

See [Security Expressions](../expressions/index.md) for full expression syntax.

## @permit_all

Mark endpoints as explicitly public:

```rust
use actix_security::permit_all;

#[permit_all]
#[get("/health")]
async fn health_check() -> impl Responder {
    HttpResponse::Ok().body("OK")
}
```

> **Note**: The handler doesn't receive `AuthenticatedUser` since no auth is required.

## @deny_all

Block all access (useful for deprecated endpoints):

```rust
use actix_security::deny_all;

#[deny_all]
#[get("/deprecated/endpoint")]
async fn deprecated_endpoint(_user: AuthenticatedUser) -> impl Responder {
    // This code is never reached
    HttpResponse::Ok().body("Never executed")
}
```

## @roles_allowed

Java EE style role checking (alias for `@secured`):

```rust
use actix_security::roles_allowed;

#[roles_allowed("ADMIN")]
#[get("/admin")]
async fn admin_panel(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Admin Panel")
}

#[roles_allowed("ADMIN", "MANAGER")]
#[get("/management")]
async fn management(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Management")
}
```

## Macro Placement

**Important**: Security macros must be placed **before** the route macro:

```rust
// ✓ Correct
#[secured("ADMIN")]
#[get("/admin")]
async fn admin() -> impl Responder { /* ... */ }

// ✗ Wrong - won't work
#[get("/admin")]
#[secured("ADMIN")]
async fn admin() -> impl Responder { /* ... */ }
```

## Combining with URL Authorization

Method security and URL authorization work together:

```rust
// URL authorization
let authorizer = AuthorizationManager::request_matcher()
    .add_matcher("/api/.*", Access::new().authenticated());

// Method security adds additional checks
#[pre_authorize(authority = "posts:write")]
#[post("/api/posts")]  // URL requires authentication, method requires authority
async fn create_post(user: AuthenticatedUser) -> impl Responder { /* ... */ }
```

## Error Handling

When access is denied, the macro returns `403 Forbidden`:

```rust
#[secured("ADMIN")]
#[get("/admin")]
async fn admin(user: AuthenticatedUser) -> impl Responder {
    // If user doesn't have ADMIN role, this code never runs
    // A 403 Forbidden response is returned instead
    HttpResponse::Ok().body("Admin")
}
```

The actual implementation wraps your handler:

```rust
// Your code:
#[secured("ADMIN")]
async fn admin(user: AuthenticatedUser) -> impl Responder { /* ... */ }

// Expands to (simplified):
async fn admin(user: AuthenticatedUser) -> Result<impl Responder, AuthError> {
    if !user.has_role("ADMIN") {
        return Err(AuthError::Forbidden);
    }
    Ok(/* your original code */)
}
```

## Complete Example

```rust
use actix_web::{get, post, delete, App, HttpServer, HttpResponse, Responder};
use actix_security::{secured, pre_authorize, permit_all, deny_all};
use actix_security::http::security::AuthenticatedUser;

// Public endpoints
#[permit_all]
#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Welcome!")
}

// Authenticated users
#[pre_authorize(authenticated)]
#[get("/dashboard")]
async fn dashboard(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Hello, {}!", user.get_username()))
}

// Role-based
#[secured("USER")]
#[get("/profile")]
async fn profile(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Profile")
}

// Authority-based
#[pre_authorize(authority = "posts:write")]
#[post("/posts")]
async fn create_post(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Created().body("Post created")
}

// Complex expression
#[pre_authorize("hasRole('ADMIN') OR (hasRole('USER') AND hasAuthority('posts:delete'))")]
#[delete("/posts/{id}")]
async fn delete_post(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Post deleted")
}

// Deprecated
#[deny_all]
#[get("/old-api")]
async fn old_api(_user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Never reached")
}
```

## Spring Security Comparison

**Spring Security:**
```java
@Secured("ROLE_ADMIN")
@GetMapping("/admin")
public String admin() { return "admin"; }

@PreAuthorize("hasRole('USER') and hasAuthority('posts:write')")
@PostMapping("/posts")
public String createPost() { return "created"; }

@PermitAll
@GetMapping("/public")
public String publicEndpoint() { return "public"; }

@DenyAll
@GetMapping("/deprecated")
public String deprecated() { return "never"; }

@RolesAllowed({"ADMIN", "MANAGER"})
@GetMapping("/management")
public String management() { return "management"; }
```

**Actix Security:**
```rust
#[secured("ADMIN")]
#[get("/admin")]
async fn admin() -> impl Responder { /* ... */ }

#[pre_authorize("hasRole('USER') AND hasAuthority('posts:write')")]
#[post("/posts")]
async fn create_post() -> impl Responder { /* ... */ }

#[permit_all]
#[get("/public")]
async fn public_endpoint() -> impl Responder { /* ... */ }

#[deny_all]
#[get("/deprecated")]
async fn deprecated() -> impl Responder { /* ... */ }

#[roles_allowed("ADMIN", "MANAGER")]
#[get("/management")]
async fn management() -> impl Responder { /* ... */ }
```
