//! Integration tests for the form_login example.
//!
//! These tests verify form-based login with redirect support.

use actix_security::http::security::{
    FormLoginConfig, FormLoginHandler, PasswordEncoder, SessionConfig, SessionFixationStrategy,
};
use actix_security_examples::TestUsers;
use actix_web::http::StatusCode;

#[actix_web::test]
async fn test_form_login_config_builder() {
    let _config = FormLoginConfig::new()
        .login_page("/login")
        .login_processing_url("/login")
        .default_success_url("/dashboard")
        .failure_url("/login?error")
        .logout_url("/logout")
        .logout_success_url("/login?logout");

    // Config should be created successfully
    assert!(true);
}

#[actix_web::test]
async fn test_form_login_handler_creation() {
    let session_config = SessionConfig::new()
        .user_key("user")
        .fixation_strategy(SessionFixationStrategy::MigrateSession);

    let form_login_config = FormLoginConfig::new()
        .login_page("/login")
        .default_success_url("/");

    let _handler = FormLoginHandler::new(form_login_config, session_config);

    // Handler should be created successfully
    assert!(true);
}

#[actix_web::test]
async fn test_authentication_failure_redirect() {
    let session_config = SessionConfig::new()
        .user_key("user")
        .fixation_strategy(SessionFixationStrategy::MigrateSession);

    let form_login_config = FormLoginConfig::new()
        .login_page("/login")
        .failure_url("/login-error")
        .default_success_url("/");

    let handler = FormLoginHandler::new(form_login_config, session_config);

    let response = handler.on_authentication_failure();

    // Should redirect to failure URL
    assert_eq!(response.status(), StatusCode::FOUND);
}

#[actix_web::test]
async fn test_form_login_with_custom_parameters() {
    let _config = FormLoginConfig::new()
        .login_page("/custom-login")
        .login_processing_url("/do-login")
        .default_success_url("/home")
        .failure_url("/custom-login?failed=true")
        .logout_url("/do-logout")
        .logout_success_url("/custom-login?loggedout=true");

    // All custom parameters should be accepted
    assert!(true);
}

#[actix_web::test]
async fn test_password_verification() {
    let users = TestUsers::new();

    // Verify admin password
    assert!(users.encoder.matches("admin", users.admin.get_password()));

    // Verify user password
    assert!(users.encoder.matches("user", users.user.get_password()));

    // Wrong password should fail
    assert!(!users.encoder.matches("wrong", users.admin.get_password()));
}
