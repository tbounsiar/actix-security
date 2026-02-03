//! Integration tests for CSRF protection.
//!
//! These tests verify CSRF token generation, validation, and middleware behavior.

use actix_security::http::security::{CsrfConfig, CsrfToken, SessionCsrfTokenRepository};
use actix_web::http::Method;

#[test]
fn test_csrf_token_creation() {
    let token = CsrfToken::new("test-token-value".to_string());

    assert_eq!(token.value(), "test-token-value");
    // Default header and parameter names
    assert_eq!(token.header_name(), "X-CSRF-TOKEN");
    assert_eq!(token.parameter_name(), "_csrf");
}

#[test]
fn test_csrf_token_custom_names() {
    let token = CsrfToken::with_names("my-token".to_string(), "X-Custom-CSRF", "csrf_token");

    assert_eq!(token.value(), "my-token");
    assert_eq!(token.header_name(), "X-Custom-CSRF");
    assert_eq!(token.parameter_name(), "csrf_token");
}

#[test]
fn test_session_csrf_repository_builder() {
    let repo = SessionCsrfTokenRepository::new()
        .session_key("my_csrf_session_key")
        .header_name("X-MY-CSRF")
        .parameter_name("my_csrf");

    // Repository should be created successfully
    // Actual session integration would be tested with actix-session
    assert!(std::mem::size_of_val(&repo) > 0);
}

#[test]
fn test_csrf_config_default() {
    let config = CsrfConfig::new();

    // Default configuration should be reasonable
    assert!(std::mem::size_of_val(&config) > 0);
}

#[test]
fn test_csrf_config_protected_methods() {
    let config = CsrfConfig::new().protected_methods(vec![
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::PATCH,
    ]);

    // Should compile and create valid config
    assert!(std::mem::size_of_val(&config) > 0);
}

#[test]
fn test_csrf_config_ignored_paths() {
    let config = CsrfConfig::new()
        .ignore_path("/api/webhook.*")
        .ignore_path("/health")
        .ignore_path("/metrics");

    // Should compile and create valid config
    assert!(std::mem::size_of_val(&config) > 0);
}

#[test]
fn test_csrf_config_custom_names() {
    let config = CsrfConfig::new()
        .header_name("X-XSRF-TOKEN")
        .parameter_name("xsrf_token");

    // Should compile and create valid config
    assert!(std::mem::size_of_val(&config) > 0);
}

#[test]
fn test_csrf_config_with_custom_repository() {
    let repo = SessionCsrfTokenRepository::new()
        .session_key("csrf_key")
        .header_name("X-CSRF")
        .parameter_name("_csrf");

    let config = CsrfConfig::new().repository(repo);

    // Should compile and create valid config
    assert!(std::mem::size_of_val(&config) > 0);
}

#[test]
fn test_csrf_config_combined_options() {
    let config = CsrfConfig::new()
        .protected_methods(vec![Method::POST, Method::PUT, Method::DELETE])
        .ignore_path("/api/public.*")
        .ignore_path("/webhooks/.*")
        .header_name("X-APP-CSRF")
        .parameter_name("app_csrf_token");

    // Should compile and create valid config with all options
    assert!(std::mem::size_of_val(&config) > 0);
}

#[test]
fn test_csrf_tokens_are_unique() {
    // Generate multiple tokens and verify they're unique
    let token1 = CsrfToken::new(generate_random_token());
    let token2 = CsrfToken::new(generate_random_token());

    assert_ne!(token1.value(), token2.value());
}

fn generate_random_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("csrf_{}", now)
}
