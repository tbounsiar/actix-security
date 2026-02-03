//! Integration tests for WebSocket security.
//!
//! These tests verify WebSocket security features including:
//! - Origin validation (CSWSH prevention)
//! - Authentication during handshake
//! - Role and authority requirements
//! - WebSocketSecurityConfig validation

use actix_security::http::security::websocket::{
    OriginValidator, WebSocketSecurityConfig, WebSocketSecurityError,
};
use actix_security::http::security::User;
use actix_web::{http::header, test, HttpMessage, HttpRequest};

// =============================================================================
// Helper Functions
// =============================================================================

/// Creates a mock HttpRequest with specified headers
fn create_request_with_origin(origin: Option<&str>) -> HttpRequest {
    let mut req = test::TestRequest::get().uri("/ws");
    if let Some(o) = origin {
        req = req.insert_header((header::ORIGIN, o));
    }
    req.to_http_request()
}

/// Creates a mock HttpRequest with user stored in extensions
fn create_request_with_user(origin: Option<&str>, user: Option<User>) -> HttpRequest {
    let mut req = test::TestRequest::get().uri("/ws");
    if let Some(o) = origin {
        req = req.insert_header((header::ORIGIN, o));
    }
    let req = req.to_http_request();
    if let Some(u) = user {
        req.extensions_mut().insert(u);
    }
    req
}

fn create_admin_user() -> User {
    User::new("admin".to_string(), String::new())
        .roles(&["ADMIN".into(), "USER".into()])
        .authorities(&["ws:connect".into(), "ws:admin".into()])
}

fn create_regular_user() -> User {
    User::new("user".to_string(), String::new())
        .roles(&["USER".into()])
        .authorities(&["ws:connect".into()])
}

fn create_guest_user() -> User {
    User::new("guest".to_string(), String::new())
        .roles(&["GUEST".into()])
        .authorities(&[])
}

// =============================================================================
// Origin Validator Tests
// =============================================================================

#[actix_web::test]
async fn test_origin_validator_exact_match() {
    let validator = OriginValidator::builder()
        .allow("http://localhost:8080")
        .allow("http://example.com")
        .build();

    // Valid origins
    let req = create_request_with_origin(Some("http://localhost:8080"));
    assert!(validator.validate(&req).is_ok());

    let req = create_request_with_origin(Some("http://example.com"));
    assert!(validator.validate(&req).is_ok());
}

#[actix_web::test]
async fn test_origin_validator_rejects_invalid_origin() {
    let validator = OriginValidator::builder()
        .allow("http://localhost:8080")
        .build();

    let req = create_request_with_origin(Some("http://evil.com"));
    let result = validator.validate(&req);
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert!(matches!(err, WebSocketSecurityError::InvalidOrigin { .. }));
}

#[actix_web::test]
async fn test_origin_validator_rejects_missing_origin_by_default() {
    let validator = OriginValidator::builder()
        .allow("http://localhost:8080")
        .build();

    let req = create_request_with_origin(None);
    let result = validator.validate(&req);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        WebSocketSecurityError::MissingOrigin
    ));
}

#[actix_web::test]
async fn test_origin_validator_allows_missing_origin_when_configured() {
    let validator = OriginValidator::builder()
        .allow("http://localhost:8080")
        .allow_missing()
        .build();

    let req = create_request_with_origin(None);
    assert!(validator.validate(&req).is_ok());
}

#[actix_web::test]
async fn test_origin_validator_wildcard_subdomain() {
    let validator = OriginValidator::builder()
        .allow_subdomain_pattern("*.example.com")
        .build();

    let req = create_request_with_origin(Some("http://api.example.com"));
    assert!(validator.validate(&req).is_ok());

    let req = create_request_with_origin(Some("http://www.example.com"));
    assert!(validator.validate(&req).is_ok());

    // Non-matching
    let req = create_request_with_origin(Some("http://evil.com"));
    assert!(validator.validate(&req).is_err());
}

#[actix_web::test]
async fn test_origin_validator_case_insensitive() {
    let validator = OriginValidator::builder()
        .allow("http://LOCALHOST:8080")
        .build();

    let req = create_request_with_origin(Some("http://localhost:8080"));
    assert!(validator.validate(&req).is_ok());

    let req = create_request_with_origin(Some("http://LOCALHOST:8080"));
    assert!(validator.validate(&req).is_ok());
}

#[actix_web::test]
async fn test_origin_validator_allows_any() {
    let validator = OriginValidator::allow_any();

    let req = create_request_with_origin(Some("http://any-origin.com"));
    assert!(validator.validate(&req).is_ok());

    let req = create_request_with_origin(Some("http://evil.com"));
    assert!(validator.validate(&req).is_ok());
}

#[actix_web::test]
async fn test_origin_validator_trailing_slash_normalization() {
    let validator = OriginValidator::builder()
        .allow("http://localhost:8080/")
        .build();

    // Without trailing slash should still match
    let req = create_request_with_origin(Some("http://localhost:8080"));
    assert!(validator.validate(&req).is_ok());
}

#[actix_web::test]
async fn test_origin_validator_multiple_origins() {
    let validator = OriginValidator::builder()
        .allow_all(&[
            "http://localhost:8080",
            "http://localhost:3000",
            "https://production.example.com",
        ])
        .build();

    let req = create_request_with_origin(Some("http://localhost:8080"));
    assert!(validator.validate(&req).is_ok());

    let req = create_request_with_origin(Some("http://localhost:3000"));
    assert!(validator.validate(&req).is_ok());

    let req = create_request_with_origin(Some("https://production.example.com"));
    assert!(validator.validate(&req).is_ok());

    let req = create_request_with_origin(Some("http://localhost:5000"));
    assert!(validator.validate(&req).is_err());
}

// =============================================================================
// WebSocketSecurityConfig Tests
// =============================================================================

#[actix_web::test]
async fn test_ws_config_default_allows_all() {
    let config = WebSocketSecurityConfig::default();

    let req = create_request_with_user(Some("http://any-origin.com"), None);
    assert!(config.validate_upgrade(&req).is_ok());
}

#[actix_web::test]
async fn test_ws_config_origin_validation() {
    let config =
        WebSocketSecurityConfig::new().allowed_origins(vec!["http://localhost:8080".into()]);

    let req = create_request_with_user(Some("http://localhost:8080"), None);
    assert!(config.validate_upgrade(&req).is_ok());

    let req = create_request_with_user(Some("http://evil.com"), None);
    assert!(config.validate_upgrade(&req).is_err());
}

#[actix_web::test]
async fn test_ws_config_authentication_required() {
    let config = WebSocketSecurityConfig::new()
        .allowed_origins(vec!["http://localhost:8080".into()])
        .require_authentication(true);

    // Without user
    let req = create_request_with_user(Some("http://localhost:8080"), None);
    let result = config.validate_upgrade(&req);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        WebSocketSecurityError::Unauthorized
    ));

    // With user
    let req = create_request_with_user(Some("http://localhost:8080"), Some(create_regular_user()));
    assert!(config.validate_upgrade(&req).is_ok());
}

#[actix_web::test]
async fn test_ws_config_role_requirement() {
    let config = WebSocketSecurityConfig::new()
        .allowed_origins(vec!["http://localhost:8080".into()])
        .require_authentication(true)
        .required_roles(vec!["ADMIN".into()]);

    // Admin user has ADMIN role
    let req = create_request_with_user(Some("http://localhost:8080"), Some(create_admin_user()));
    assert!(config.validate_upgrade(&req).is_ok());

    // Regular user does not have ADMIN role
    let req = create_request_with_user(Some("http://localhost:8080"), Some(create_regular_user()));
    let result = config.validate_upgrade(&req);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        WebSocketSecurityError::MissingRole { .. }
    ));
}

#[actix_web::test]
async fn test_ws_config_authority_requirement() {
    let config = WebSocketSecurityConfig::new()
        .allowed_origins(vec!["http://localhost:8080".into()])
        .require_authentication(true)
        .required_authorities(vec!["ws:admin".into()]);

    // Admin user has ws:admin authority
    let req = create_request_with_user(Some("http://localhost:8080"), Some(create_admin_user()));
    assert!(config.validate_upgrade(&req).is_ok());

    // Regular user does not have ws:admin authority
    let req = create_request_with_user(Some("http://localhost:8080"), Some(create_regular_user()));
    let result = config.validate_upgrade(&req);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        WebSocketSecurityError::MissingAuthority { .. }
    ));
}

#[actix_web::test]
async fn test_ws_config_combined_requirements() {
    let config = WebSocketSecurityConfig::new()
        .allowed_origins(vec!["http://localhost:8080".into()])
        .require_authentication(true)
        .required_roles(vec!["USER".into()])
        .required_authorities(vec!["ws:connect".into()]);

    // Admin user passes all checks
    let req = create_request_with_user(Some("http://localhost:8080"), Some(create_admin_user()));
    assert!(config.validate_upgrade(&req).is_ok());

    // Regular user passes all checks
    let req = create_request_with_user(Some("http://localhost:8080"), Some(create_regular_user()));
    assert!(config.validate_upgrade(&req).is_ok());

    // Guest user fails (no ws:connect authority)
    let req = create_request_with_user(Some("http://localhost:8080"), Some(create_guest_user()));
    assert!(config.validate_upgrade(&req).is_err());
}

#[actix_web::test]
async fn test_ws_config_validation_order() {
    // Validation order: origin -> auth -> roles -> authorities
    let config = WebSocketSecurityConfig::new()
        .allowed_origins(vec!["http://localhost:8080".into()])
        .require_authentication(true)
        .required_roles(vec!["ADMIN".into()]);

    // Bad origin fails first
    let req = create_request_with_user(Some("http://evil.com"), Some(create_admin_user()));
    let result = config.validate_upgrade(&req);
    assert!(matches!(
        result.unwrap_err(),
        WebSocketSecurityError::InvalidOrigin { .. }
    ));

    // Good origin, no auth fails second
    let req = create_request_with_user(Some("http://localhost:8080"), None);
    let result = config.validate_upgrade(&req);
    assert!(matches!(
        result.unwrap_err(),
        WebSocketSecurityError::Unauthorized
    ));

    // Good origin, auth, wrong role fails third
    let req = create_request_with_user(Some("http://localhost:8080"), Some(create_guest_user()));
    let result = config.validate_upgrade(&req);
    assert!(matches!(
        result.unwrap_err(),
        WebSocketSecurityError::MissingRole { .. }
    ));
}

// =============================================================================
// WebSocket Upgrade Result Tests
// =============================================================================

#[actix_web::test]
async fn test_ws_upgrade_contains_user() {
    let config = WebSocketSecurityConfig::new()
        .allowed_origins(vec!["http://localhost:8080".into()])
        .require_authentication(true);

    let user = create_admin_user();
    let req = create_request_with_user(Some("http://localhost:8080"), Some(user.clone()));

    let upgrade = config.validate_upgrade(&req).unwrap();
    assert!(upgrade.is_authenticated());
    assert_eq!(upgrade.username(), Some("admin"));

    let extracted_user = upgrade.user();
    assert!(extracted_user.is_some());
    assert_eq!(extracted_user.unwrap().get_username(), "admin");
}

#[actix_web::test]
async fn test_ws_upgrade_contains_origin() {
    let config =
        WebSocketSecurityConfig::new().allowed_origins(vec!["http://localhost:8080".into()]);

    let req = create_request_with_user(Some("http://localhost:8080"), None);
    let upgrade = config.validate_upgrade(&req).unwrap();

    assert_eq!(upgrade.origin(), Some("http://localhost:8080"));
}

#[actix_web::test]
async fn test_ws_upgrade_anonymous_user() {
    let config =
        WebSocketSecurityConfig::new().allowed_origins(vec!["http://localhost:8080".into()]);

    let req = create_request_with_user(Some("http://localhost:8080"), None);
    let upgrade = config.validate_upgrade(&req).unwrap();

    assert!(!upgrade.is_authenticated());
    assert_eq!(upgrade.username(), None);
    assert!(upgrade.user().is_none());
}

// =============================================================================
// Error Response Tests
// =============================================================================

#[actix_web::test]
async fn test_ws_security_error_unauthorized_status() {
    use actix_web::ResponseError;

    let err = WebSocketSecurityError::Unauthorized;
    assert_eq!(err.status_code(), actix_web::http::StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn test_ws_security_error_forbidden_status() {
    use actix_web::ResponseError;

    let err = WebSocketSecurityError::MissingRole {
        role: "ADMIN".into(),
    };
    assert_eq!(err.status_code(), actix_web::http::StatusCode::FORBIDDEN);

    let err = WebSocketSecurityError::MissingAuthority {
        authority: "ws:admin".into(),
    };
    assert_eq!(err.status_code(), actix_web::http::StatusCode::FORBIDDEN);

    let err = WebSocketSecurityError::InvalidOrigin {
        origin: "http://evil.com".into(),
    };
    assert_eq!(err.status_code(), actix_web::http::StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn test_ws_security_error_missing_origin_status() {
    use actix_web::ResponseError;

    let err = WebSocketSecurityError::MissingOrigin;
    assert_eq!(err.status_code(), actix_web::http::StatusCode::FORBIDDEN);
}

// =============================================================================
// Builder Pattern Tests
// =============================================================================

#[actix_web::test]
async fn test_ws_config_builder_pattern() {
    // Verify fluent builder pattern works correctly
    let config = WebSocketSecurityConfig::new()
        .allowed_origins(vec!["http://localhost:8080".into()])
        .require_authentication(true)
        .required_roles(vec!["USER".into()])
        .required_authorities(vec!["ws:connect".into()]);

    // The config should work as expected
    let req = create_request_with_user(Some("http://localhost:8080"), Some(create_regular_user()));
    assert!(config.validate_upgrade(&req).is_ok());
}

#[actix_web::test]
async fn test_origin_validator_builder_pattern() {
    let validator = OriginValidator::builder()
        .allow("http://localhost:8080")
        .allow("http://localhost:3000")
        .allow_subdomain_pattern("*.example.com")
        .allow_localhost_in_dev(true)
        .build();

    // All configured origins should work
    let req = create_request_with_origin(Some("http://localhost:8080"));
    assert!(validator.validate(&req).is_ok());

    let req = create_request_with_origin(Some("http://api.example.com"));
    assert!(validator.validate(&req).is_ok());
}
