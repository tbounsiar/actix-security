//! Integration tests for OAuth2 authentication.
//!
//! These tests verify OAuth2 configuration, provider setup, and user handling.
//! Note: Full OAuth2 flow requires external providers, so these tests focus on
//! the configurable and testable components.

use actix_security::http::security::oauth2::{OAuth2Config, OAuth2Error, OAuth2Provider};

// =============================================================================
// OAuth2Config Tests
// =============================================================================

#[actix_web::test]
async fn test_oauth2_config_google() {
    let config = OAuth2Config::new(
        "test-client-id",
        "test-client-secret",
        "http://localhost:8080/oauth2/callback/google",
    )
    .registration_id("google")
    .provider(OAuth2Provider::Google);

    assert_eq!(config.registration_id, "google");
    assert_eq!(config.client_id, "test-client-id");
    assert_eq!(config.client_secret, "test-client-secret");
    assert_eq!(
        config.redirect_uri,
        "http://localhost:8080/oauth2/callback/google"
    );
    assert_eq!(config.provider, OAuth2Provider::Google);
}

#[actix_web::test]
async fn test_oauth2_config_github() {
    let config = OAuth2Config::new(
        "github-client-id",
        "github-client-secret",
        "http://localhost:8080/oauth2/callback/github",
    )
    .registration_id("github")
    .provider(OAuth2Provider::GitHub);

    assert_eq!(config.provider, OAuth2Provider::GitHub);
    // GitHub uses OAuth2 only, not OIDC
    assert!(!OAuth2Provider::GitHub.supports_oidc());
}

#[actix_web::test]
async fn test_oauth2_config_keycloak() {
    let config = OAuth2Config::new(
        "keycloak-client-id",
        "keycloak-client-secret",
        "http://localhost:8080/oauth2/callback/keycloak",
    )
    .registration_id("keycloak")
    .provider(OAuth2Provider::Keycloak);

    assert_eq!(config.provider, OAuth2Provider::Keycloak);
}

#[actix_web::test]
async fn test_oauth2_config_custom_provider() {
    let config = OAuth2Config::new(
        "custom-client-id",
        "custom-client-secret",
        "http://localhost:8080/oauth2/callback/custom",
    )
    .registration_id("custom")
    .provider(OAuth2Provider::Custom)
    .authorization_uri("https://custom.example.com/oauth/authorize")
    .token_uri("https://custom.example.com/oauth/token")
    .userinfo_uri("https://custom.example.com/oauth/userinfo");

    assert_eq!(config.provider, OAuth2Provider::Custom);
    assert_eq!(
        config.authorization_uri,
        Some("https://custom.example.com/oauth/authorize".to_string())
    );
    assert_eq!(
        config.token_uri,
        Some("https://custom.example.com/oauth/token".to_string())
    );
    assert_eq!(
        config.userinfo_uri,
        Some("https://custom.example.com/oauth/userinfo".to_string())
    );
}

#[actix_web::test]
async fn test_oauth2_config_custom_scopes() {
    let config = OAuth2Config::new(
        "test-client-id",
        "test-client-secret",
        "http://localhost:8080/oauth2/callback/google",
    )
    .provider(OAuth2Provider::Google)
    .scopes(vec![
        "openid".to_string(),
        "email".to_string(),
        "profile".to_string(),
        "calendar".to_string(),
    ]);

    assert!(config.scopes.contains(&"openid".to_string()));
    assert!(config.scopes.contains(&"email".to_string()));
    assert!(config.scopes.contains(&"calendar".to_string()));
}

#[actix_web::test]
async fn test_oauth2_config_pkce() {
    // PKCE is enabled by default
    let config = OAuth2Config::new(
        "test-client-id",
        "test-client-secret",
        "http://localhost:8080/oauth2/callback/google",
    )
    .provider(OAuth2Provider::Google);

    assert!(config.use_pkce);
}

#[actix_web::test]
async fn test_oauth2_config_username_attribute() {
    let config = OAuth2Config::new(
        "test-client-id",
        "test-client-secret",
        "http://localhost:8080/oauth2/callback/github",
    )
    .provider(OAuth2Provider::GitHub)
    .username_attribute("login");

    assert_eq!(config.username_attribute, "login");
}

// =============================================================================
// OAuth2Provider Tests
// =============================================================================

#[actix_web::test]
async fn test_provider_oidc_support() {
    // Providers with OIDC support
    assert!(OAuth2Provider::Google.supports_oidc());
    assert!(OAuth2Provider::Microsoft.supports_oidc());
    assert!(OAuth2Provider::Apple.supports_oidc());
    assert!(OAuth2Provider::Okta.supports_oidc());
    assert!(OAuth2Provider::Auth0.supports_oidc());
    assert!(OAuth2Provider::Keycloak.supports_oidc());

    // Providers without OIDC support
    assert!(!OAuth2Provider::GitHub.supports_oidc());
    assert!(!OAuth2Provider::Facebook.supports_oidc());
    assert!(!OAuth2Provider::Custom.supports_oidc());
}

#[actix_web::test]
async fn test_provider_default_scopes() {
    // Google defaults include openid
    let google_scopes = OAuth2Provider::Google.default_scopes();
    assert!(google_scopes.contains(&"openid"));
    assert!(google_scopes.contains(&"email"));
    assert!(google_scopes.contains(&"profile"));

    // GitHub doesn't have openid
    let github_scopes = OAuth2Provider::GitHub.default_scopes();
    assert!(github_scopes.contains(&"read:user"));
}

#[actix_web::test]
async fn test_provider_auth_url_google() {
    let auth_url = OAuth2Provider::Google.auth_url();
    assert!(auth_url.is_some());
    assert!(auth_url.unwrap().contains("google.com"));
}

#[actix_web::test]
async fn test_provider_token_url_google() {
    let token_url = OAuth2Provider::Google.token_url();
    assert!(token_url.is_some());
    assert!(token_url.unwrap().contains("google"));
}

#[actix_web::test]
async fn test_provider_userinfo_url_google() {
    let userinfo_url = OAuth2Provider::Google.userinfo_url();
    assert!(userinfo_url.is_some());
    assert!(userinfo_url.unwrap().contains("google"));
}

#[actix_web::test]
async fn test_provider_discovery_url() {
    // Google supports OIDC discovery
    let google_discovery = OAuth2Provider::Google.discovery_url();
    assert!(google_discovery.is_some());
    assert!(google_discovery
        .unwrap()
        .contains(".well-known/openid-configuration"));

    // GitHub doesn't support OIDC discovery
    let github_discovery = OAuth2Provider::GitHub.discovery_url();
    assert!(github_discovery.is_none());
}

// =============================================================================
// OAuth2 Error Tests
// =============================================================================

#[actix_web::test]
async fn test_oauth2_error_types() {
    let config_err = OAuth2Error::Configuration("Missing client_id".to_string());
    assert!(format!("{}", config_err).contains("Missing client_id"));

    let discovery_err = OAuth2Error::Discovery("Failed to fetch .well-known".to_string());
    assert!(format!("{}", discovery_err).contains("Discovery"));

    let token_err = OAuth2Error::TokenExchange("Invalid code".to_string());
    assert!(format!("{}", token_err).contains("Token"));

    let state_err = OAuth2Error::InvalidState("State mismatch".to_string());
    assert!(format!("{}", state_err).contains("State"));

    let nonce_err = OAuth2Error::InvalidNonce("Nonce mismatch".to_string());
    assert!(format!("{}", nonce_err).contains("Nonce"));
}

// =============================================================================
// Multiple Providers Configuration Tests
// =============================================================================

#[actix_web::test]
async fn test_multiple_oauth2_providers() {
    let google_config = OAuth2Config::new(
        "google-client-id",
        "google-secret",
        "http://localhost:8080/oauth2/callback/google",
    )
    .registration_id("google")
    .provider(OAuth2Provider::Google);

    let github_config = OAuth2Config::new(
        "github-client-id",
        "github-secret",
        "http://localhost:8080/oauth2/callback/github",
    )
    .registration_id("github")
    .provider(OAuth2Provider::GitHub);

    let microsoft_config = OAuth2Config::new(
        "ms-client-id",
        "ms-secret",
        "http://localhost:8080/oauth2/callback/microsoft",
    )
    .registration_id("microsoft")
    .provider(OAuth2Provider::Microsoft);

    assert_eq!(google_config.registration_id, "google");
    assert_eq!(github_config.registration_id, "github");
    assert_eq!(microsoft_config.registration_id, "microsoft");

    // Each provider should have unique characteristics
    assert!(google_config.provider.supports_oidc());
    assert!(!github_config.provider.supports_oidc());
    assert!(microsoft_config.provider.supports_oidc());
}

// =============================================================================
// PKCE and Security Tests
// =============================================================================

#[actix_web::test]
async fn test_oauth2_github_no_pkce() {
    // GitHub doesn't support PKCE, so setting it as provider should disable PKCE
    let config = OAuth2Config::new(
        "test-client-id",
        "test-client-secret",
        "http://localhost:8080/oauth2/callback/github",
    )
    .provider(OAuth2Provider::GitHub);

    // GitHub provider should have PKCE disabled
    assert!(!config.use_pkce);
}

// =============================================================================
// Scope Customization Tests
// =============================================================================

#[actix_web::test]
async fn test_custom_scopes_override_defaults() {
    let config = OAuth2Config::new(
        "test-client-id",
        "test-client-secret",
        "http://localhost:8080/oauth2/callback/google",
    )
    .provider(OAuth2Provider::Google)
    .scopes(vec!["custom_scope_only".to_string()]);

    // Custom scopes should replace defaults
    assert_eq!(config.scopes.len(), 1);
    assert!(config.scopes.contains(&"custom_scope_only".to_string()));
}

#[actix_web::test]
async fn test_provider_sets_default_scopes() {
    let config = OAuth2Config::new(
        "test-client-id",
        "test-client-secret",
        "http://localhost:8080/oauth2/callback/google",
    )
    .provider(OAuth2Provider::Google);

    // Provider should set default scopes
    assert!(!config.scopes.is_empty());
    // Google defaults include openid, email, profile
    assert!(config.scopes.contains(&"openid".to_string()));
}

// =============================================================================
// Registration ID Tests
// =============================================================================

#[actix_web::test]
async fn test_auto_registration_id() {
    // When registration_id is not set, it should be auto-generated from provider
    let config = OAuth2Config::new(
        "test-client-id",
        "test-client-secret",
        "http://localhost:8080/oauth2/callback/google",
    )
    .provider(OAuth2Provider::Google);

    // Should be auto-set to lowercase provider name
    assert_eq!(config.registration_id, "google");
}

#[actix_web::test]
async fn test_explicit_registration_id() {
    let config = OAuth2Config::new(
        "test-client-id",
        "test-client-secret",
        "http://localhost:8080/oauth2/callback/google",
    )
    .registration_id("my-google-oauth")
    .provider(OAuth2Provider::Google);

    // Explicit ID should be preserved
    assert_eq!(config.registration_id, "my-google-oauth");
}
