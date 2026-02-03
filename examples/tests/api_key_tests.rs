//! Integration tests for the api_key_auth example.
//!
//! These tests verify API Key authentication with various key locations
//! (header, query parameter, Authorization header) and access control.

use actix_security::http::security::api_key::{
    ApiKey, ApiKeyAuthenticator, ApiKeyConfig, ApiKeyLocation, ApiKeyRepository,
    InMemoryApiKeyRepository,
};
use actix_security::http::security::middleware::SecurityTransform;
use actix_security::http::security::web::{Access, RequestMatcherAuthorizer};
use actix_security::http::security::{AuthenticatedUser, AuthorizationManager};
use actix_security_examples::server::{assert_forbidden, assert_ok, assert_unauthorized};
use actix_web::{get, test, web, App, HttpResponse, Responder};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

// =============================================================================
// Test Handlers
// =============================================================================

#[get("/public")]
async fn public_endpoint() -> impl Responder {
    HttpResponse::Ok().body("Public")
}

#[get("/api/data")]
async fn api_data(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("API User: {}", user.get_username()))
}

#[get("/api/admin")]
async fn api_admin(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Admin: {}", user.get_username()))
}

#[get("/api/write")]
async fn api_write(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Write: {}", user.get_username()))
}

// =============================================================================
// Test Infrastructure
// =============================================================================

// Global repository for all tests (using OnceLock for function pointer compatibility)
static TEST_REPOSITORY: OnceLock<Arc<InMemoryApiKeyRepository>> = OnceLock::new();

fn get_test_repository() -> Arc<InMemoryApiKeyRepository> {
    TEST_REPOSITORY
        .get_or_init(|| {
            Arc::new(
                InMemoryApiKeyRepository::new()
                    // Standard API key with read access
                    .with_key(
                        ApiKey::new("sk_live_abc123")
                            .name("Production API Key")
                            .roles(vec!["API_USER".into()])
                            .authorities(vec!["api:read".into()]),
                    )
                    // API key with write access
                    .with_key(
                        ApiKey::new("sk_live_write_key")
                            .name("Write Access Key")
                            .roles(vec!["API_USER".into()])
                            .authorities(vec!["api:read".into(), "api:write".into()]),
                    )
                    // Admin API key
                    .with_key(
                        ApiKey::new("sk_live_admin_key")
                            .name("Admin API Key")
                            .roles(vec!["API_USER".into(), "ADMIN".into()])
                            .authorities(vec![
                                "api:read".into(),
                                "api:write".into(),
                                "api:admin".into(),
                            ]),
                    )
                    // Disabled API key
                    .with_key(
                        ApiKey::new("sk_disabled_key")
                            .name("Disabled Key")
                            .enabled(false)
                            .roles(vec!["API_USER".into()]),
                    ),
            )
        })
        .clone()
}

fn test_authenticator() -> ApiKeyAuthenticator<InMemoryApiKeyRepository> {
    ApiKeyAuthenticator::with_shared_repository(get_test_repository()).config(
        ApiKeyConfig::new()
            .add_location(ApiKeyLocation::header("X-API-Key"))
            .add_location(ApiKeyLocation::authorization("ApiKey"))
            .add_location(ApiKeyLocation::query("api_key"))
            .validate_expiration(true)
            .validate_enabled(true)
            .realm("Test API"),
    )
}

fn test_authorizer() -> RequestMatcherAuthorizer {
    AuthorizationManager::request_matcher()
        .http_basic() // Use HTTP-style 401 response for unauthenticated requests
        // Use exact patterns to avoid HashMap ordering issues (HashMap doesn't preserve order)
        .add_matcher("^/api/admin$", Access::new().roles(vec!["ADMIN"]))
        .add_matcher("^/api/write$", Access::new().authorities(vec!["api:write"]))
        .add_matcher("^/api/data$", Access::new().roles(vec!["API_USER"]))
}

async fn create_test_app() -> impl actix_web::dev::Service<
    actix_http::Request,
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
> {
    test::init_service(
        App::new().service(
            web::scope("")
                .wrap(
                    SecurityTransform::new()
                        .config_authenticator(test_authenticator)
                        .config_authorizer(test_authorizer),
                )
                .service(public_endpoint)
                .service(api_data)
                .service(api_admin)
                .service(api_write),
        ),
    )
    .await
}

// =============================================================================
// API Key in Header Tests
// =============================================================================

#[actix_web::test]
async fn test_api_key_in_header_valid() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/api/data")
        .insert_header(("X-API-Key", "sk_live_abc123"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_ok(&resp);
}

#[actix_web::test]
async fn test_api_key_in_header_invalid() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/api/data")
        .insert_header(("X-API-Key", "invalid_key"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_unauthorized(&resp);
}

#[actix_web::test]
async fn test_api_key_missing() {
    let app = create_test_app().await;

    let req = test::TestRequest::get().uri("/api/data").to_request();

    let resp = test::call_service(&app, req).await;
    assert_unauthorized(&resp);
}

// =============================================================================
// API Key in Query Parameter Tests
// =============================================================================

#[actix_web::test]
async fn test_api_key_in_query_valid() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/api/data?api_key=sk_live_abc123")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_ok(&resp);
}

#[actix_web::test]
async fn test_api_key_in_query_invalid() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/api/data?api_key=invalid_key")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_unauthorized(&resp);
}

// =============================================================================
// API Key in Authorization Header Tests
// =============================================================================

#[actix_web::test]
async fn test_api_key_in_authorization_header_valid() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/api/data")
        .insert_header(("Authorization", "ApiKey sk_live_abc123"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_ok(&resp);
}

#[actix_web::test]
async fn test_api_key_in_authorization_header_wrong_scheme() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/api/data")
        .insert_header(("Authorization", "Bearer sk_live_abc123"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_unauthorized(&resp);
}

// =============================================================================
// API Key State Tests (Disabled)
// =============================================================================

#[actix_web::test]
async fn test_api_key_disabled() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/api/data")
        .insert_header(("X-API-Key", "sk_disabled_key"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_unauthorized(&resp);
}

// =============================================================================
// Role-Based Access Control Tests
// =============================================================================

#[actix_web::test]
async fn test_api_key_admin_access_granted() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/api/admin")
        .insert_header(("X-API-Key", "sk_live_admin_key"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_ok(&resp);
}

#[actix_web::test]
async fn test_api_key_admin_access_denied() {
    let app = create_test_app().await;

    // Regular API key should not have ADMIN role
    let req = test::TestRequest::get()
        .uri("/api/admin")
        .insert_header(("X-API-Key", "sk_live_abc123"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_forbidden(&resp);
}

// =============================================================================
// Authority-Based Access Control Tests
// =============================================================================

#[actix_web::test]
async fn test_api_key_write_authority_granted() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/api/write")
        .insert_header(("X-API-Key", "sk_live_write_key"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_ok(&resp);
}

#[actix_web::test]
async fn test_api_key_write_authority_denied() {
    let app = create_test_app().await;

    // Read-only API key should not have api:write authority
    let req = test::TestRequest::get()
        .uri("/api/write")
        .insert_header(("X-API-Key", "sk_live_abc123"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_forbidden(&resp);
}

// =============================================================================
// Public Endpoint Tests
// =============================================================================

#[actix_web::test]
async fn test_public_endpoint_no_key() {
    let app = create_test_app().await;

    // Note: The RequestMatcherAuthorizer requires authentication for all URLs
    // except the login page. Public endpoints need an API key.
    let req = test::TestRequest::get().uri("/public").to_request();

    let resp = test::call_service(&app, req).await;
    assert_unauthorized(&resp);
}

#[actix_web::test]
async fn test_public_endpoint_with_key() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/public")
        .insert_header(("X-API-Key", "sk_live_abc123"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_ok(&resp);
}

// =============================================================================
// Header Priority Tests
// =============================================================================

#[actix_web::test]
async fn test_api_key_header_takes_priority() {
    let app = create_test_app().await;

    // Both header and query have keys - header should be used
    let req = test::TestRequest::get()
        .uri("/api/data?api_key=invalid_key")
        .insert_header(("X-API-Key", "sk_live_abc123"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_ok(&resp);
}

// =============================================================================
// API Key Model Unit Tests
// =============================================================================

#[actix_web::test]
async fn test_api_key_creation() {
    let key = ApiKey::new("sk_test_key")
        .name("Test Key")
        .roles(vec!["TEST_ROLE".into()])
        .authorities(vec!["test:read".into()]);

    assert!(key.is_enabled());
    assert!(!key.is_expired());
    assert!(key.is_valid());
    assert!(key.has_role("TEST_ROLE"));
    assert!(key.has_authority("test:read"));
}

#[actix_web::test]
async fn test_api_key_expiration() {
    let key = ApiKey::new("sk_test_expired").expires_in(Duration::from_secs(0));

    // Wait a bit for expiration
    tokio::time::sleep(Duration::from_millis(10)).await;

    assert!(key.is_expired());
    assert!(!key.is_valid());
}

#[actix_web::test]
async fn test_api_key_disabled_model() {
    let key = ApiKey::new("sk_test_disabled").enabled(false);

    assert!(!key.is_enabled());
    assert!(!key.is_valid());
}

#[actix_web::test]
async fn test_api_key_metadata() {
    let key = ApiKey::new("sk_test_meta")
        .with_metadata("environment", "test")
        .with_metadata("tier", "premium");

    assert_eq!(
        key.get_metadata().get("environment"),
        Some(&"test".to_string())
    );
    assert_eq!(key.get_metadata().get("tier"), Some(&"premium".to_string()));
    assert_eq!(key.get_metadata().get("nonexistent"), None);
}

// =============================================================================
// API Key Config Tests
// =============================================================================

#[actix_web::test]
async fn test_api_key_config_default() {
    let config = ApiKeyConfig::default();

    // Default config should have one default location (X-API-Key header)
    assert_eq!(config.get_locations().len(), 1);
}

#[actix_web::test]
async fn test_api_key_config_header() {
    let config = ApiKeyConfig::header("X-API-Key");

    assert_eq!(config.get_locations().len(), 1);
}

#[actix_web::test]
async fn test_api_key_config_query() {
    let config = ApiKeyConfig::query("api_key");

    assert_eq!(config.get_locations().len(), 1);
}

#[actix_web::test]
async fn test_api_key_config_authorization() {
    let config = ApiKeyConfig::authorization("ApiKey");

    assert_eq!(config.get_locations().len(), 1);
}

#[actix_web::test]
async fn test_api_key_config_multiple_locations() {
    let config = ApiKeyConfig::new()
        .add_location(ApiKeyLocation::header("Custom-API-Key"))
        .add_location(ApiKeyLocation::authorization("ApiKey"))
        .add_location(ApiKeyLocation::query("api_key"));

    // new() creates default location + 3 added = 4
    assert_eq!(config.get_locations().len(), 4);
}

// =============================================================================
// Repository Tests
// =============================================================================

#[actix_web::test]
async fn test_repository_find_by_key() {
    let repo =
        InMemoryApiKeyRepository::new().with_key(ApiKey::new("sk_find_test").name("Find Test"));

    let found = repo.find_by_key("sk_find_test");
    assert!(found.is_some());

    let not_found = repo.find_by_key("nonexistent");
    assert!(not_found.is_none());
}

#[actix_web::test]
async fn test_repository_add_and_remove() {
    let repo = InMemoryApiKeyRepository::new();

    repo.add_key(ApiKey::new("sk_add_test"));
    assert!(repo.find_by_key("sk_add_test").is_some());

    repo.remove_key("sk_add_test");
    assert!(repo.find_by_key("sk_add_test").is_none());
}

#[actix_web::test]
async fn test_repository_get_all_keys() {
    let repo = InMemoryApiKeyRepository::new()
        .with_key(ApiKey::new("sk_1"))
        .with_key(ApiKey::new("sk_2"))
        .with_key(ApiKey::new("sk_3"));

    let all_keys = repo.get_all_keys();
    assert_eq!(all_keys.len(), 3);
}
