//! Integration tests for remember-me authentication.
//!
//! These tests verify the remember-me token creation, validation, and cookie handling.

use actix_security::http::security::{RememberMeConfig, RememberMeServices, User};
use std::time::Duration;

#[test]
fn test_remember_me_config_builder() {
    let config = RememberMeConfig::new("super-secret-key")
        .token_validity_days(30)
        .cookie_name("app-remember-me")
        .cookie_secure(true)
        .cookie_http_only(true)
        .parameter_name("remember");

    assert_eq!(config.get_key(), "super-secret-key");
    assert_eq!(
        config.get_token_validity(),
        Duration::from_secs(30 * 24 * 60 * 60)
    );
    assert_eq!(config.get_cookie_name(), "app-remember-me");
    assert_eq!(config.get_parameter_name(), "remember");
}

#[test]
fn test_remember_me_config_validity_seconds() {
    let config = RememberMeConfig::new("secret").token_validity_seconds(7200);

    assert_eq!(config.get_token_validity(), Duration::from_secs(7200));
}

#[test]
fn test_remember_me_always_remember() {
    let config_default = RememberMeConfig::new("secret");
    assert!(!config_default.is_always_remember());

    let config_always = RememberMeConfig::new("secret").always_remember(true);
    assert!(config_always.is_always_remember());
}

#[test]
fn test_remember_me_login_creates_valid_cookie() {
    let config = RememberMeConfig::new("test-secret")
        .token_validity_days(7)
        .cookie_secure(false);

    let services = RememberMeServices::new(config);
    let user = User::new("alice".to_string(), "password".to_string()).roles(&["USER".into()]);

    let cookie = services.login_success(&user);

    // Verify cookie properties
    assert_eq!(cookie.name(), "remember-me");
    assert!(!cookie.value().is_empty());

    // Verify token can be validated
    let username = services.auto_login(cookie.value());
    assert_eq!(username, Some("alice".to_string()));
}

#[test]
fn test_remember_me_logout_clears_cookie() {
    let config = RememberMeConfig::new("secret").cookie_name("my-remember-me");

    let services = RememberMeServices::new(config);
    let logout_cookie = services.logout();

    assert_eq!(logout_cookie.name(), "my-remember-me");
    assert_eq!(logout_cookie.value(), "");
}

#[test]
fn test_remember_me_invalid_tokens_rejected() {
    let config = RememberMeConfig::new("secret");
    let services = RememberMeServices::new(config);

    // Empty token
    assert!(services.auto_login("").is_none());

    // Random string
    assert!(services.auto_login("random-invalid-string").is_none());

    // Valid base64 but invalid structure
    let invalid_base64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        "not:a:valid:token:format",
    );
    assert!(services.auto_login(&invalid_base64).is_none());
}

#[test]
fn test_remember_me_wrong_secret_rejected() {
    let config1 = RememberMeConfig::new("secret1");
    let config2 = RememberMeConfig::new("secret2");

    let services1 = RememberMeServices::new(config1);
    let services2 = RememberMeServices::new(config2);

    let user = User::new("bob".to_string(), "pass".to_string());
    let cookie = services1.login_success(&user);

    // Token created with secret1 should not validate with secret2
    assert!(services2.auto_login(cookie.value()).is_none());
}

#[test]
fn test_remember_me_services_accessors() {
    let config = RememberMeConfig::new("secret")
        .cookie_name("custom-cookie")
        .parameter_name("rememberMe")
        .always_remember(true);

    let services = RememberMeServices::new(config);

    assert_eq!(services.cookie_name(), "custom-cookie");
    assert_eq!(services.parameter_name(), "rememberMe");
    assert!(services.is_always_remember());
}

#[test]
fn test_remember_me_multiple_users() {
    let config = RememberMeConfig::new("shared-secret");
    let services = RememberMeServices::new(config);

    let user1 = User::new("user1".to_string(), "pass1".to_string());
    let user2 = User::new("user2".to_string(), "pass2".to_string());

    let cookie1 = services.login_success(&user1);
    let cookie2 = services.login_success(&user2);

    // Each user should get a valid token
    assert_eq!(
        services.auto_login(cookie1.value()),
        Some("user1".to_string())
    );
    assert_eq!(
        services.auto_login(cookie2.value()),
        Some("user2".to_string())
    );

    // Tokens should be different
    assert_ne!(cookie1.value(), cookie2.value());
}
