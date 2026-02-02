//! HTTP Basic Authentication Example
//!
//! This example demonstrates HTTP Basic authentication with Actix Security.
//!
//! # Run
//! ```bash
//! cargo run --example basic_auth
//! ```
//!
//! # Test
//! ```bash
//! # Successful authentication
//! curl -u admin:admin http://localhost:8080/
//! curl -u user:user http://localhost:8080/
//!
//! # Access admin-only route
//! curl -u admin:admin http://localhost:8080/admin
//! curl -u user:user http://localhost:8080/admin  # 403 Forbidden
//!
//! # Without authentication
//! curl http://localhost:8080/  # 401 Unauthorized
//! ```

use actix_security::http::security::{
    middleware::SecurityTransform, Argon2PasswordEncoder, AuthenticatedUser,
    AuthenticationManager, AuthorizationManager, PasswordEncoder, User,
};
use actix_security::http::security::web::{Access, MemoryAuthenticator, RequestMatcherAuthorizer};
use actix_web::{get, App, HttpResponse, HttpServer, Responder};

/// Creates the authenticator with users stored in memory.
fn authenticator() -> MemoryAuthenticator {
    let encoder = Argon2PasswordEncoder::new();

    AuthenticationManager::in_memory_authentication()
        .password_encoder(encoder.clone())
        .with_user(
            User::with_encoded_password("admin", encoder.encode("admin"))
                .roles(&["ADMIN".into(), "USER".into()])
                .authorities(&["users:read".into(), "users:write".into()]),
        )
        .with_user(
            User::with_encoded_password("user", encoder.encode("user"))
                .roles(&["USER".into()])
                .authorities(&["users:read".into()]),
        )
}

/// Creates the authorizer with URL-based access control.
fn authorizer() -> RequestMatcherAuthorizer {
    AuthorizationManager::request_matcher()
        .http_basic() // Enable HTTP Basic Authentication
        .add_matcher("/admin.*", Access::new().roles(vec!["ADMIN"]))
        .add_matcher("/api/.*", Access::new().authorities(vec!["users:read"]))
}

#[get("/")]
async fn index(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Hello, {}! Your roles: {:?}",
        user.get_username(),
        user.get_roles()
    ))
}

#[get("/admin")]
async fn admin(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Welcome to admin panel, {}!",
        user.get_username()
    ))
}

#[get("/api/users")]
async fn api_users(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "users": ["alice", "bob", "charlie"],
        "requested_by": user.get_username()
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    println!("=== HTTP Basic Authentication Example ===");
    println!("Server running at http://localhost:8080");
    println!();
    println!("Test users:");
    println!("  admin:admin - Roles: [ADMIN, USER]");
    println!("  user:user   - Roles: [USER]");
    println!();
    println!("Try:");
    println!("  curl -u admin:admin http://localhost:8080/");
    println!("  curl -u admin:admin http://localhost:8080/admin");
    println!("  curl -u user:user http://localhost:8080/admin  # 403");
    println!();

    HttpServer::new(move || {
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(authenticator)
                    .config_authorizer(authorizer),
            )
            .service(index)
            .service(admin)
            .service(api_users)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
