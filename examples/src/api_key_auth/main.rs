//! API Key Authentication Example
//!
//! This example demonstrates how to use API Key authentication to secure
//! service-to-service communication or public APIs.
//!
//! ## Running the example
//!
//! ```bash
//! cargo run -p actix-security-examples --bin api_key_auth
//! ```
//!
//! ## Testing with curl
//!
//! ```bash
//! # Without API key (redirects to /login)
//! curl http://127.0.0.1:8080/api/data
//!
//! # With valid API key in header
//! curl -H "X-API-Key: sk_live_abc123" http://127.0.0.1:8080/api/data
//!
//! # With admin API key
//! curl -H "X-API-Key: sk_live_admin_key" http://127.0.0.1:8080/api/admin
//!
//! # With API key in query parameter
//! curl "http://127.0.0.1:8080/api/data?api_key=sk_live_abc123"
//!
//! # With API key in Authorization header
//! curl -H "Authorization: ApiKey sk_live_abc123" http://127.0.0.1:8080/api/data
//!
//! # Public endpoint (no API key needed)
//! curl http://127.0.0.1:8080/public
//! ```

use actix_security::http::security::api_key::{
    ApiKey, ApiKeyAuthenticator, ApiKeyConfig, ApiKeyLocation, InMemoryApiKeyRepository,
};
use actix_security::http::security::middleware::SecurityTransform;
use actix_security::http::security::web::{Access, RequestMatcherAuthorizer};
use actix_security::http::security::{AuthenticatedUser, AuthorizationManager};
use actix_web::{get, App, HttpResponse, HttpServer, Responder};
use std::sync::Arc;
use std::time::Duration;

/// Public endpoint - no authentication required
#[get("/public")]
async fn public_endpoint() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "This is a public endpoint",
        "authenticated": false
    }))
}

/// Protected API endpoint - requires valid API key with API_USER role
#[get("/api/data")]
async fn api_data(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "API data retrieved successfully",
        "user": user.get_username(),
        "roles": user.get_roles(),
        "authorities": user.get_authorities()
    }))
}

/// Admin API endpoint - requires API key with ADMIN role
#[get("/api/admin")]
async fn api_admin(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Admin data retrieved successfully",
        "user": user.get_username(),
        "is_admin": true
    }))
}

/// Endpoint showing API key info
#[get("/api/me")]
async fn api_me(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "api_key_name": user.get_username(),
        "roles": user.get_roles(),
        "authorities": user.get_authorities()
    }))
}

/// Health check endpoint
#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy"
    }))
}

// Shared repository (using lazy_static pattern for thread safety)
use std::sync::OnceLock;
static REPOSITORY: OnceLock<Arc<InMemoryApiKeyRepository>> = OnceLock::new();

fn get_repository() -> Arc<InMemoryApiKeyRepository> {
    REPOSITORY
        .get_or_init(|| {
            Arc::new(
                InMemoryApiKeyRepository::new()
                    // Standard API key
                    .with_key(
                        ApiKey::new("sk_live_abc123")
                            .name("Production API Key")
                            .owner("service-a@example.com")
                            .roles(vec!["API_USER".into()])
                            .authorities(vec!["api:read".into()])
                            .with_metadata("environment", "production"),
                    )
                    // API key with write access
                    .with_key(
                        ApiKey::new("sk_live_write_key")
                            .name("Write Access Key")
                            .owner("service-b@example.com")
                            .roles(vec!["API_USER".into()])
                            .authorities(vec!["api:read".into(), "api:write".into()])
                            .with_metadata("environment", "production"),
                    )
                    // Admin API key
                    .with_key(
                        ApiKey::new("sk_live_admin_key")
                            .name("Admin API Key")
                            .owner("admin@example.com")
                            .roles(vec!["API_USER".into(), "ADMIN".into()])
                            .authorities(vec![
                                "api:read".into(),
                                "api:write".into(),
                                "api:admin".into(),
                            ])
                            .with_metadata("environment", "production"),
                    )
                    // Test API key with expiration
                    .with_key(
                        ApiKey::new("sk_test_temp_key")
                            .name("Temporary Test Key")
                            .owner("tester@example.com")
                            .roles(vec!["API_USER".into()])
                            .authorities(vec!["api:read".into()])
                            .expires_in(Duration::from_secs(3600 * 24)) // Expires in 24 hours
                            .with_metadata("environment", "test"),
                    )
                    // Disabled API key (for testing)
                    .with_key(
                        ApiKey::new("sk_disabled_key")
                            .name("Disabled Key")
                            .owner("old-service@example.com")
                            .enabled(false)
                            .roles(vec!["API_USER".into()]),
                    ),
            )
        })
        .clone()
}

/// Creates the API key authenticator
fn authenticator() -> ApiKeyAuthenticator<InMemoryApiKeyRepository> {
    ApiKeyAuthenticator::with_shared_repository(get_repository()).config(
        ApiKeyConfig::new()
            // Check header first (recommended)
            .add_location(ApiKeyLocation::header("X-API-Key"))
            // Then check Authorization header with "ApiKey" scheme
            .add_location(ApiKeyLocation::authorization("ApiKey"))
            // Finally check query parameter (for testing/debugging)
            .add_location(ApiKeyLocation::query("api_key"))
            .realm("API Service"),
    )
}

/// Creates the authorizer with URL-based access control
fn authorizer() -> RequestMatcherAuthorizer {
    AuthorizationManager::request_matcher()
        // Admin endpoints require ADMIN role
        .add_matcher("/api/admin.*", Access::new().roles(vec!["ADMIN"]))
        // All other /api/* endpoints require API_USER role
        .add_matcher("/api/.*", Access::new().roles(vec!["API_USER"]))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    println!("=== API Key Authentication Example ===");
    println!("Server running at http://127.0.0.1:8080");
    println!();
    println!("Available API keys:");
    println!("  sk_live_abc123      - Roles: [API_USER], Authorities: [api:read]");
    println!("  sk_live_write_key   - Roles: [API_USER], Authorities: [api:read, api:write]");
    println!("  sk_live_admin_key   - Roles: [API_USER, ADMIN], Authorities: [api:read, api:write, api:admin]");
    println!("  sk_test_temp_key    - Temporary key (expires in 24h)");
    println!("  sk_disabled_key     - Disabled key (will be rejected)");
    println!();
    println!("Try:");
    println!(
        "  curl http://127.0.0.1:8080/public                                 # Public endpoint"
    );
    println!("  curl http://127.0.0.1:8080/health                                 # Health check");
    println!("  curl -H 'X-API-Key: sk_live_abc123' http://127.0.0.1:8080/api/data");
    println!("  curl -H 'X-API-Key: sk_live_admin_key' http://127.0.0.1:8080/api/admin");
    println!("  curl -H 'Authorization: ApiKey sk_live_abc123' http://127.0.0.1:8080/api/me");
    println!("  curl 'http://127.0.0.1:8080/api/data?api_key=sk_live_abc123'");
    println!();

    HttpServer::new(move || {
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(authenticator)
                    .config_authorizer(authorizer),
            )
            .service(public_endpoint)
            .service(api_data)
            .service(api_admin)
            .service(api_me)
            .service(health)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
