//! Audit Logging Example
//!
//! This example demonstrates security audit logging with tracing integration.
//!
//! ## Running the example
//!
//! ```bash
//! cargo run -p actix-security-examples --bin audit_logging
//! ```
//!
//! ## Testing with curl
//!
//! ```bash
//! # Public endpoint (no logging for successful auth)
//! curl http://127.0.0.1:8080/public
//!
//! # Successful authentication (watch the console for INFO logs)
//! curl -u admin:admin http://127.0.0.1:8080/api/data
//!
//! # Failed authentication (watch for WARNING logs)
//! curl -u admin:wrong http://127.0.0.1:8080/api/data
//!
//! # Access denied (watch for WARNING logs)
//! curl -u user:user http://127.0.0.1:8080/admin
//!
//! # Admin access (successful)
//! curl -u admin:admin http://127.0.0.1:8080/admin
//! ```

use actix_security::http::security::middleware::SecurityTransform;
use actix_security::http::security::web::{Access, RequestMatcherAuthorizer};
use actix_security::http::security::{
    Argon2PasswordEncoder, AuditLogger, AuthenticatedUser, AuthenticationManager,
    AuthorizationManager, PasswordEncoder, SecurityEvent, SecurityEventType, StdoutHandler,
    TracingHandler, User,
};
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use tracing_subscriber::EnvFilter;

/// Public endpoint - no authentication required
#[get("/public")]
async fn public_endpoint() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "This is a public endpoint",
        "authenticated": false
    }))
}

/// Protected API endpoint - requires USER role
#[get("/api/data")]
async fn api_data(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "API data retrieved successfully",
        "user": user.get_username(),
        "roles": user.get_roles()
    }))
}

/// Admin endpoint - requires ADMIN role
#[get("/admin")]
async fn admin_endpoint(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Admin endpoint",
        "user": user.get_username(),
        "is_admin": true
    }))
}

/// Endpoint that manually logs an audit event
#[get("/api/action")]
async fn perform_action(
    user: AuthenticatedUser,
    audit_logger: web::Data<AuditLogger>,
) -> impl Responder {
    // Log a custom security event
    audit_logger.log(
        SecurityEvent::new(SecurityEventType::Custom("ACTION_PERFORMED".to_string()))
            .username(user.get_username())
            .path("/api/action")
            .detail("action", "data_export"),
    );

    HttpResponse::Ok().json(serde_json::json!({
        "message": "Action performed",
        "user": user.get_username()
    }))
}

/// Health check
#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy"
    }))
}

fn authenticator() -> impl actix_security::http::security::Authenticator {
    let encoder = Argon2PasswordEncoder::new();

    AuthenticationManager::in_memory_authentication()
        .password_encoder(encoder.clone())
        .with_user(
            User::with_encoded_password("admin", encoder.encode("admin"))
                .roles(&["ADMIN".into(), "USER".into()]),
        )
        .with_user(
            User::with_encoded_password("user", encoder.encode("user")).roles(&["USER".into()]),
        )
}

fn authorizer() -> RequestMatcherAuthorizer {
    AuthorizationManager::request_matcher()
        .http_basic()
        .add_matcher("/admin.*", Access::new().roles(vec!["ADMIN"]))
        .add_matcher("/api/.*", Access::new().roles(vec!["USER"]))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize tracing subscriber with environment filter
    // You can set RUST_LOG=actix_security::audit=debug for more verbose output
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("actix_security::audit=info".parse().unwrap())
                .add_directive("actix_web=info".parse().unwrap()),
        )
        .init();

    // Create audit logger with multiple handlers
    let audit_logger = AuditLogger::new()
        // TracingHandler emits events through the tracing crate
        .add_handler(TracingHandler::new())
        // StdoutHandler prints formatted events (optional, for demo)
        .add_handler(StdoutHandler::new());

    let audit_logger_data = web::Data::new(audit_logger);

    println!("=== Audit Logging Example ===");
    println!("Server running at http://127.0.0.1:8080");
    println!();
    println!("Users:");
    println!("  admin:admin - Roles: [ADMIN, USER]");
    println!("  user:user   - Roles: [USER]");
    println!();
    println!("Watch the console for security audit events!");
    println!();
    println!("Try:");
    println!("  curl http://127.0.0.1:8080/public              # Public (no auth)");
    println!("  curl -u admin:admin http://127.0.0.1:8080/api/data  # Success");
    println!("  curl -u admin:wrong http://127.0.0.1:8080/api/data  # Auth failure");
    println!("  curl -u user:user http://127.0.0.1:8080/admin       # Access denied");
    println!("  curl -u admin:admin http://127.0.0.1:8080/admin     # Admin access");
    println!("  curl -u admin:admin http://127.0.0.1:8080/api/action # Custom event");
    println!();

    HttpServer::new(move || {
        App::new()
            .app_data(audit_logger_data.clone())
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(authenticator)
                    .config_authorizer(authorizer),
            )
            .service(public_endpoint)
            .service(api_data)
            .service(admin_endpoint)
            .service(perform_action)
            .service(health)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
