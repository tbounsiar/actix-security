//! Integration tests for the jwt_auth example.
//!
//! These tests verify JWT token generation, validation, and refresh token flow.

use actix_security::http::security::{JwtAuthenticator, JwtConfig, JwtTokenService};
use actix_security_examples::TestUsers;

/// Create JWT service for tests.
fn create_jwt_service() -> JwtTokenService {
    let jwt_config = JwtConfig::new("test-secret-key-for-jwt")
        .issuer("test-issuer")
        .audience("test-audience")
        .expiration_secs(3600);

    JwtTokenService::new(jwt_config).refresh_expiration_days(1)
}

#[actix_web::test]
async fn test_generate_token_for_valid_user() {
    let users = TestUsers::new();
    let jwt_service = create_jwt_service();

    let result = jwt_service.generate_token(&users.admin);
    assert!(result.is_ok());

    let token = result.unwrap();
    assert!(!token.is_empty());
}

#[actix_web::test]
async fn test_generate_token_pair() {
    let users = TestUsers::new();
    let jwt_service = create_jwt_service();

    let result = jwt_service.generate_token_pair(&users.admin);
    assert!(result.is_ok());

    let pair = result.unwrap();
    assert!(!pair.access_token.is_empty());
    assert!(pair.refresh_token.is_some());
    assert_eq!(pair.token_type, "Bearer");
    assert!(pair.expires_in > 0);
}

#[actix_web::test]
async fn test_validate_token() {
    let users = TestUsers::new();
    let jwt_service = create_jwt_service();

    // Generate token
    let token = jwt_service.generate_token(&users.admin).unwrap();

    // Validate token
    let jwt_config = JwtConfig::new("test-secret-key-for-jwt")
        .issuer("test-issuer")
        .audience("test-audience");
    let authenticator = JwtAuthenticator::new(jwt_config);

    let result = authenticator.validate_token(&token);
    assert!(result.is_ok());

    let token_data = result.unwrap();
    assert_eq!(token_data.claims.sub, "admin");
    assert!(token_data.claims.roles.contains(&"ADMIN".to_string()));
    assert!(token_data.claims.roles.contains(&"USER".to_string()));
}

#[actix_web::test]
async fn test_validate_token_with_wrong_secret() {
    let users = TestUsers::new();
    let jwt_service = create_jwt_service();

    // Generate token
    let token = jwt_service.generate_token(&users.admin).unwrap();

    // Try to validate with wrong secret
    let jwt_config = JwtConfig::new("wrong-secret-key")
        .issuer("test-issuer")
        .audience("test-audience");
    let authenticator = JwtAuthenticator::new(jwt_config);

    let result = authenticator.validate_token(&token);
    assert!(result.is_err());
}

#[actix_web::test]
async fn test_refresh_token_flow() {
    let users = TestUsers::new();
    let jwt_service = create_jwt_service();

    // Generate initial token pair
    let pair = jwt_service.generate_token_pair(&users.admin).unwrap();
    let refresh_token = pair.refresh_token.unwrap();

    // Refresh tokens
    let result = jwt_service.refresh_tokens(&refresh_token);
    assert!(result.is_ok());

    let new_pair = result.unwrap();
    assert!(!new_pair.access_token.is_empty());
    // New access token should be different
    assert_ne!(new_pair.access_token, pair.access_token);
}

#[actix_web::test]
async fn test_invalid_refresh_token() {
    let jwt_service = create_jwt_service();

    let result = jwt_service.refresh_tokens("invalid-refresh-token");
    assert!(result.is_err());
}

#[actix_web::test]
async fn test_token_contains_user_info() {
    let users = TestUsers::new();
    let jwt_service = create_jwt_service();

    let pair = jwt_service.generate_token_pair(&users.user).unwrap();

    let jwt_config = JwtConfig::new("test-secret-key-for-jwt")
        .issuer("test-issuer")
        .audience("test-audience");
    let authenticator = JwtAuthenticator::new(jwt_config);

    let token_data = authenticator.validate_token(&pair.access_token).unwrap();

    assert_eq!(token_data.claims.sub, "user");
    assert!(token_data.claims.roles.contains(&"USER".to_string()));
    assert!(!token_data.claims.roles.contains(&"ADMIN".to_string()));
    assert!(token_data
        .claims
        .authorities
        .contains(&"users:read".to_string()));
}
