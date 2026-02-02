# @deny_all

Blocks all access to an endpoint. Always returns `403 Forbidden`.

## Syntax

```rust
#[deny_all]
```

## Usage

```rust
use actix_web::{get, HttpResponse, Responder};
use actix_security::deny_all;
use actix_security::http::security::AuthenticatedUser;

#[deny_all]
#[get("/disabled")]
async fn disabled_endpoint(_user: AuthenticatedUser) -> impl Responder {
    // This code is never executed
    HttpResponse::Ok().body("Never reached")
}
```

## Common Use Cases

### Temporarily Disable Endpoints

```rust
// Disable an endpoint for maintenance
#[deny_all]
#[post("/payments/process")]
async fn process_payment(_user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Processing")
}
```

### Deprecate Endpoints

```rust
// Mark old API version as deprecated
#[deny_all]
#[get("/api/v1/users")]
async fn v1_users(_user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Old API")
}
```

### Placeholder for Future Features

```rust
// Reserve endpoint for future implementation
#[deny_all]
#[get("/premium/advanced-analytics")]
async fn advanced_analytics(_user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Coming soon")
}
```

### Security Lockdown

```rust
// Emergency lockdown of sensitive endpoints
#[deny_all]
#[delete("/admin/database")]
async fn delete_database(_user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Deleted")
}
```

## AuthenticatedUser Parameter

The handler should have an `AuthenticatedUser` parameter (typically prefixed with `_` since it's unused):

```rust
#[deny_all]
#[get("/disabled")]
async fn disabled(_user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Never reached")
}
```

The `_user` parameter is needed for type inference, even though the handler code is never executed.

## Response

Always returns:

```
HTTP/1.1 403 Forbidden
Content-Length: 0
```

Regardless of:
- User authentication status
- User roles or authorities
- Request method or body

## How It Works

The macro replaces your handler with one that immediately returns `Forbidden`:

```rust
// Input
#[deny_all]
#[get("/disabled")]
async fn disabled(_user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Never reached")
}

// Expansion (simplified)
#[get("/disabled")]
async fn disabled(_user: AuthenticatedUser) -> Result<impl Responder, AuthError> {
    return Err(AuthError::Forbidden);

    // Unreachable - kept for type inference
    #[allow(unreachable_code)]
    Ok(HttpResponse::Ok().body("Never reached"))
}
```

## Spring Security / Java EE Comparison

**Spring Security / Java EE:**
```java
@DenyAll
@GetMapping("/disabled")
public String disabled() {
    return "never reached";
}
```

**Actix Security:**
```rust
#[deny_all]
#[get("/disabled")]
async fn disabled(_user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("never reached")
}
```

## When to Use

Use `#[deny_all]` when:
- Temporarily disabling an endpoint
- Deprecating old API versions
- Reserving endpoints for future use
- Emergency security lockdown

Consider removing the endpoint entirely if it's permanently disabled.

## Alternatives

### Return Custom Error

If you want to return a custom message:

```rust
#[get("/deprecated")]
async fn deprecated() -> impl Responder {
    HttpResponse::Gone().body("This endpoint has been deprecated. Use /api/v2 instead.")
}
```

### Conditional Disable

If you want to conditionally disable:

```rust
#[get("/feature")]
async fn feature(user: AuthenticatedUser) -> impl Responder {
    if !feature_flag_enabled("new_feature") {
        return HttpResponse::ServiceUnavailable()
            .body("Feature temporarily disabled");
    }
    HttpResponse::Ok().body("Feature content")
}
```
