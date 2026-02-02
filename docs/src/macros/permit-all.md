# @permit_all

Marks an endpoint as publicly accessible. No authentication required.

## Syntax

```rust
#[permit_all]
```

## Usage

```rust
use actix_web::{get, HttpResponse, Responder};
use actix_security::permit_all;

#[permit_all]
#[get("/health")]
async fn health_check() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

#[permit_all]
#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Welcome!")
}
```

## No AuthenticatedUser Required

Unlike other security macros, `#[permit_all]` handlers don't need an `AuthenticatedUser` parameter since no authentication is required:

```rust
// ✓ Correct - no AuthenticatedUser needed
#[permit_all]
#[get("/public")]
async fn public_endpoint() -> impl Responder {
    HttpResponse::Ok().body("Public content")
}

// ✓ Also valid - AuthenticatedUser is optional
#[permit_all]
#[get("/info")]
async fn info(user: Option<AuthenticatedUser>) -> impl Responder {
    match user {
        Some(u) => HttpResponse::Ok().body(format!("Hello, {}!", u.get_username())),
        None => HttpResponse::Ok().body("Hello, guest!"),
    }
}
```

## Common Use Cases

### Health Checks

```rust
#[permit_all]
#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

#[permit_all]
#[get("/ready")]
async fn readiness() -> impl Responder {
    // Check database, etc.
    HttpResponse::Ok().body("Ready")
}
```

### Public API Endpoints

```rust
#[permit_all]
#[get("/api/public/version")]
async fn api_version() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "version": "1.0.0"
    }))
}
```

### Landing Pages

```rust
#[permit_all]
#[get("/")]
async fn home() -> impl Responder {
    HttpResponse::Ok().body("Welcome to our app!")
}

#[permit_all]
#[get("/about")]
async fn about() -> impl Responder {
    HttpResponse::Ok().body("About us")
}
```

### Login/Registration

```rust
#[permit_all]
#[get("/login")]
async fn login_page() -> impl Responder {
    HttpResponse::Ok().body("Login form")
}

#[permit_all]
#[post("/login")]
async fn do_login(form: web::Form<LoginForm>) -> impl Responder {
    // Process login
    HttpResponse::Ok().body("Logged in")
}

#[permit_all]
#[post("/register")]
async fn register(form: web::Form<RegisterForm>) -> impl Responder {
    // Process registration
    HttpResponse::Created().body("Registered")
}
```

## Important Note

`#[permit_all]` marks the **handler** as public, but URL-based authorization still applies. If your URL matcher requires authentication for the path, users will still need to authenticate.

To make an endpoint truly public, ensure your URL matcher doesn't require authentication for that path:

```rust
// URL authorization
let authorizer = AuthorizationManager::request_matcher()
    .add_matcher("/api/private/.*", Access::new().authenticated())
    // /api/public/.* has no matcher, so it's public by default
    ;

// Handler authorization
#[permit_all]  // Explicitly marks handler as public
#[get("/api/public/info")]
async fn public_info() -> impl Responder {
    HttpResponse::Ok().body("Public info")
}
```

## How It Works

The macro simply passes through your function unchanged:

```rust
// Input
#[permit_all]
#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

// Output (unchanged)
#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().body("OK")
}
```

The macro serves as documentation and ensures consistency with other security annotations.

## Spring Security / Java EE Comparison

**Spring Security / Java EE:**
```java
@PermitAll
@GetMapping("/public")
public String publicEndpoint() {
    return "public";
}
```

**Actix Security:**
```rust
#[permit_all]
#[get("/public")]
async fn public_endpoint() -> impl Responder {
    HttpResponse::Ok().body("public")
}
```

## When to Use

Use `#[permit_all]` for:
- Health check endpoints
- Public API endpoints
- Login/registration pages
- Landing pages
- Any endpoint that should be accessible without authentication

Consider using URL-based authorization instead when you have many public endpoints under a common path prefix.
