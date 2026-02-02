# Your First Secured App

This guide walks you through building a complete secured application step by step.

## What We'll Build

A simple REST API with:
- Public endpoints (no auth required)
- User-only endpoints (requires USER role)
- Admin-only endpoints (requires ADMIN role)
- Authority-based endpoints (requires specific permissions)

## Project Setup

```bash
cargo new my-secured-app
cd my-secured-app
```

Update `Cargo.toml`:

```toml
[package]
name = "my-secured-app"
version = "0.1.0"
edition = "2021"

[dependencies]
actix-web = "4"
actix-security = { version = "0.2", features = ["argon2", "http-basic"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Step 1: Define Your Users

First, create a function that configures your user store:

```rust
use actix_security::http::security::{
    AuthenticationManager, Argon2PasswordEncoder, PasswordEncoder, User,
};
use actix_security::http::security::web::MemoryAuthenticator;

fn create_authenticator(encoder: Argon2PasswordEncoder) -> MemoryAuthenticator {
    AuthenticationManager::in_memory_authentication()
        .password_encoder(encoder.clone())
        // Admin user with full access
        .with_user(
            User::with_encoded_password("admin", encoder.encode("admin123"))
                .roles(&["ADMIN".into(), "USER".into()])
                .authorities(&[
                    "users:read".into(),
                    "users:write".into(),
                    "posts:read".into(),
                    "posts:write".into(),
                ])
        )
        // Regular user
        .with_user(
            User::with_encoded_password("user", encoder.encode("user123"))
                .roles(&["USER".into()])
                .authorities(&["posts:read".into()])
        )
        // Guest with limited access
        .with_user(
            User::with_encoded_password("guest", encoder.encode("guest123"))
                .roles(&["GUEST".into()])
        )
}
```

## Step 2: Configure URL-Based Authorization

Create rules for URL patterns:

```rust
use actix_security::http::security::{AuthorizationManager, Access};
use actix_security::http::security::web::RequestMatcherAuthorizer;

fn create_authorizer() -> RequestMatcherAuthorizer {
    AuthorizationManager::request_matcher()
        .login_url("/login")
        .http_basic()
        // Admin section requires ADMIN role
        .add_matcher("/admin/.*", Access::new().roles(vec!["ADMIN"]))
        // API requires authentication
        .add_matcher("/api/.*", Access::new().authenticated())
        // Everything else is public
}
```

## Step 3: Create Your Handlers

```rust
use actix_web::{get, post, web, HttpResponse, Responder};
use actix_security::{secured, pre_authorize, permit_all};
use actix_security::http::security::AuthenticatedUser;

// ============= Public Endpoints =============

#[permit_all]
#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Welcome to My App!")
}

#[permit_all]
#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

// ============= User Endpoints =============

#[secured("USER")]
#[get("/profile")]
async fn get_profile(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Profile for: {}\nRoles: {:?}\nAuthorities: {:?}",
        user.get_username(),
        user.get_roles(),
        user.get_authorities()
    ))
}

#[pre_authorize("hasRole('USER') AND hasAuthority('posts:read')")]
#[get("/posts")]
async fn list_posts(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Posts for {}", user.get_username()))
}

#[pre_authorize(authority = "posts:write")]
#[post("/posts")]
async fn create_post(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Created().body(format!("Post created by {}", user.get_username()))
}

// ============= Admin Endpoints =============

#[secured("ADMIN")]
#[get("/admin/dashboard")]
async fn admin_dashboard(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Admin Dashboard - Welcome {}!", user.get_username()))
}

#[pre_authorize("hasRole('ADMIN') AND hasAuthority('users:write')")]
#[post("/admin/users")]
async fn create_user(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Created().body("User created")
}
```

## Step 4: Wire It All Together

```rust
use actix_web::{App, HttpServer};
use actix_security::http::security::middleware::SecurityTransform;
use actix_security::http::security::SecurityHeaders;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("🚀 Starting secured server at http://127.0.0.1:8080");

    let encoder = Argon2PasswordEncoder::new();

    HttpServer::new(move || {
        let enc = encoder.clone();
        App::new()
            // Add security headers
            .wrap(SecurityHeaders::default())
            // Add authentication & authorization
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(move || create_authenticator(enc.clone()))
                    .config_authorizer(create_authorizer)
            )
            // Register routes
            .service(index)
            .service(health)
            .service(get_profile)
            .service(list_posts)
            .service(create_post)
            .service(admin_dashboard)
            .service(create_user)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Step 5: Test Your Application

```bash
# Start the server
cargo run
```

### Test Public Endpoints

```bash
curl http://127.0.0.1:8080/
# Output: Welcome to My App!

curl http://127.0.0.1:8080/health
# Output: OK
```

### Test User Endpoints

```bash
# Guest can't access profile
curl -u guest:guest123 http://127.0.0.1:8080/profile
# Output: 403 Forbidden

# User can access profile
curl -u user:user123 http://127.0.0.1:8080/profile
# Output: Profile for: user...

# User can read posts
curl -u user:user123 http://127.0.0.1:8080/posts
# Output: Posts for user

# User can't create posts (no posts:write authority)
curl -X POST -u user:user123 http://127.0.0.1:8080/posts
# Output: 403 Forbidden
```

### Test Admin Endpoints

```bash
# Admin can access everything
curl -u admin:admin123 http://127.0.0.1:8080/admin/dashboard
# Output: Admin Dashboard - Welcome admin!

curl -X POST -u admin:admin123 http://127.0.0.1:8080/posts
# Output: Post created by admin

curl -X POST -u admin:admin123 http://127.0.0.1:8080/admin/users
# Output: User created

# Regular user can't access admin
curl -u user:user123 http://127.0.0.1:8080/admin/dashboard
# Output: 403 Forbidden
```

## Complete Source Code

See the full working example in the [test crate](https://github.com/your-org/actix-security/tree/main/test).

## Next Steps

- Learn about different [Authentication](../authentication/index.md) methods
- Explore [Authorization](../authorization/index.md) patterns
- Master [Security Expressions](../expressions/index.md)
- Add [Security Headers](../features/security-headers.md)
