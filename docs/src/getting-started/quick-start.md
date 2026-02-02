# Quick Start

Get up and running with Actix Security in 5 minutes.

## Prerequisites

- Rust 1.70 or later
- Cargo

## Step 1: Add Dependencies

Add the following to your `Cargo.toml`:

```toml
[dependencies]
actix-web = "4"
actix-security = { version = "0.2", features = ["argon2", "http-basic"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Step 2: Create a Simple Secured Application

```rust
use actix_web::{get, web, App, HttpServer, HttpResponse, Responder};
use actix_security::secured;
use actix_security::http::security::{
    AuthenticatedUser, AuthenticationManager, AuthorizationManager,
    Argon2PasswordEncoder, PasswordEncoder, User,
};
use actix_security::http::security::middleware::SecurityTransform;

// Public endpoint
#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Welcome! Login at /login")
}

// Secured endpoint - requires USER role
#[secured("USER")]
#[get("/profile")]
async fn profile(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Hello, {}!", user.get_username()))
}

// Admin-only endpoint
#[secured("ADMIN")]
#[get("/admin")]
async fn admin(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Admin Panel - Welcome {}!", user.get_username()))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting server at http://127.0.0.1:8080");
    println!("Try: curl -u user:password http://127.0.0.1:8080/profile");
    println!("Try: curl -u admin:admin http://127.0.0.1:8080/admin");

    let encoder = Argon2PasswordEncoder::new();

    HttpServer::new(move || {
        let enc = encoder.clone();
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(move || {
                        AuthenticationManager::in_memory_authentication()
                            .password_encoder(enc.clone())
                            .with_user(
                                User::with_encoded_password("user", enc.encode("password"))
                                    .roles(&["USER".into()])
                            )
                            .with_user(
                                User::with_encoded_password("admin", enc.encode("admin"))
                                    .roles(&["ADMIN".into(), "USER".into()])
                            )
                    })
                    .config_authorizer(|| {
                        AuthorizationManager::request_matcher()
                            .login_url("/login")
                            .http_basic()
                    })
            )
            .service(index)
            .service(profile)
            .service(admin)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Step 3: Test Your Application

```bash
# Run the server
cargo run

# Test public endpoint
curl http://127.0.0.1:8080/

# Test with user credentials
curl -u user:password http://127.0.0.1:8080/profile
# Output: Hello, user!

# Test admin endpoint with user (should fail)
curl -u user:password http://127.0.0.1:8080/admin
# Output: 403 Forbidden

# Test admin endpoint with admin
curl -u admin:admin http://127.0.0.1:8080/admin
# Output: Admin Panel - Welcome admin!
```

## What's Next?

- Learn about [Installation](./installation.md) options
- Build [Your First Secured App](./first-app.md) step by step
- Explore [Authentication](../authentication/index.md) options
- Understand [Authorization](../authorization/index.md) patterns
- Master [Security Macros](../macros/index.md)
