# @pre_authorize

Expression-based method security. The most powerful and flexible security macro.

## Syntax Options

```rust
// Simple checks
#[pre_authorize(authenticated)]               // Any authenticated user
#[pre_authorize(role = "ADMIN")]              // Single role
#[pre_authorize(authority = "users:write")]   // Single authority
#[pre_authorize(authorities = ["a", "b"])]    // Multiple authorities (OR)

// Expression syntax
#[pre_authorize("hasRole('ADMIN')")]
#[pre_authorize("hasRole('USER') AND hasAuthority('posts:write')")]
#[pre_authorize("hasAnyRole('ADMIN', 'MANAGER') OR hasAuthority('reports:view')")]
```

## Simple Checks

### Authenticated Only

```rust
#[pre_authorize(authenticated)]
#[get("/profile")]
async fn profile(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Hello, {}!", user.get_username()))
}
```

### Single Role

```rust
#[pre_authorize(role = "ADMIN")]
#[get("/admin")]
async fn admin(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Admin panel")
}
```

### Single Authority

```rust
#[pre_authorize(authority = "users:delete")]
#[delete("/users/{id}")]
async fn delete_user(user: AuthenticatedUser, path: web::Path<i64>) -> impl Responder {
    HttpResponse::Ok().body(format!("Deleted user {}", path.into_inner()))
}
```

### Multiple Authorities (OR)

```rust
#[pre_authorize(authorities = ["users:read", "users:write"])]
#[get("/users")]
async fn list_users(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().json(vec!["user1", "user2"])
}
```

## Expression Syntax

For complex authorization rules, use the expression syntax:

```rust
#[pre_authorize("expression")]
```

### Available Functions

| Function | Description |
|----------|-------------|
| `hasRole('ROLE')` | User has the specified role |
| `hasAnyRole('R1', 'R2')` | User has any of the roles |
| `hasAuthority('auth')` | User has the authority |
| `hasAnyAuthority('a1', 'a2')` | User has any of the authorities |
| `isAuthenticated()` | User is authenticated |
| `permitAll()` | Always allow |
| `denyAll()` | Always deny |

### Operators

| Operator | Description |
|----------|-------------|
| `AND` | Both conditions must be true |
| `OR` | Either condition can be true |
| `NOT` | Negates the condition |
| `( )` | Groups expressions |

## Expression Examples

### Basic Expressions

```rust
// Role check
#[pre_authorize("hasRole('ADMIN')")]

// Authority check
#[pre_authorize("hasAuthority('posts:write')")]

// Any of multiple roles
#[pre_authorize("hasAnyRole('ADMIN', 'MANAGER', 'SUPERVISOR')")]

// Any of multiple authorities
#[pre_authorize("hasAnyAuthority('posts:read', 'posts:write')")]
```

### Combining with AND

```rust
// Must have role AND authority
#[pre_authorize("hasRole('USER') AND hasAuthority('posts:write')")]
#[post("/posts")]
async fn create_post(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Created().body("Post created")
}
```

### Combining with OR

```rust
// Either admin role OR specific authority
#[pre_authorize("hasRole('ADMIN') OR hasAuthority('users:write')")]
#[put("/users/{id}")]
async fn update_user(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("User updated")
}
```

### Using NOT

```rust
// Anyone except guests
#[pre_authorize("NOT hasRole('GUEST')")]
#[get("/premium")]
async fn premium(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Premium content")
}
```

### Complex Expressions

```rust
// Admin OR (User with write permission)
#[pre_authorize("hasRole('ADMIN') OR (hasRole('USER') AND hasAuthority('posts:write'))")]
#[post("/posts")]
async fn create_post(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Created().body("Post created")
}

// Multiple conditions
#[pre_authorize("(hasAnyRole('ADMIN', 'MANAGER')) AND hasAuthority('reports:export')")]
#[get("/reports/export")]
async fn export_reports(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Exported")
}
```

### Permit All / Deny All

```rust
#[pre_authorize("permitAll()")]
#[get("/public")]
async fn public_info(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Public")
}

#[pre_authorize("denyAll()")]
#[get("/disabled")]
async fn disabled(_user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Never reached")
}
```

## Compile-Time Validation

Expressions are parsed and validated at compile time:

```rust
// ✓ Valid - compiles successfully
#[pre_authorize("hasRole('ADMIN') AND hasAuthority('users:write')")]

// ✗ Invalid - compile error: unexpected token
#[pre_authorize("hasRole('ADMIN') && hasAuthority('users:write')")]

// ✗ Invalid - compile error: unmatched parenthesis
#[pre_authorize("hasRole('ADMIN'")]

// ✗ Invalid - compile error: unknown function
#[pre_authorize("hasPermission('admin')")]
```

## Error Response

When access is denied:

```
HTTP/1.1 403 Forbidden
Content-Length: 0
```

## Spring Security Comparison

**Spring Security:**
```java
@PreAuthorize("hasRole('ADMIN')")
public void adminOnly() {}

@PreAuthorize("hasRole('USER') and hasAuthority('posts:write')")
public void createPost() {}

@PreAuthorize("hasAnyRole('ADMIN', 'MANAGER') or hasAuthority('reports:view')")
public void viewReports() {}

@PreAuthorize("isAuthenticated()")
public void authenticated() {}
```

**Actix Security:**
```rust
#[pre_authorize("hasRole('ADMIN')")]
async fn admin_only() {}

#[pre_authorize("hasRole('USER') AND hasAuthority('posts:write')")]
async fn create_post() {}

#[pre_authorize("hasAnyRole('ADMIN', 'MANAGER') OR hasAuthority('reports:view')")]
async fn view_reports() {}

#[pre_authorize("isAuthenticated()")]
async fn authenticated() {}
```

Key differences:
- Use `AND`/`OR` instead of `and`/`or` (case-insensitive but uppercase is conventional)
- Use single quotes for strings: `'ADMIN'` not `"ADMIN"`

## When to Use

Use `#[pre_authorize]` when:
- You need authority checks
- You need AND/OR/NOT logic
- You need complex expressions
- You want Spring Security-like syntax

Use `#[secured]` instead when:
- You only need simple role checks
- OR logic is sufficient
