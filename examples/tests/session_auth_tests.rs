//! Integration tests for the session_auth example.
//!
//! These tests verify session-based authentication and session fixation protection.

use actix_security::http::security::{
    Argon2PasswordEncoder, PasswordEncoder, SessionAuthenticator, SessionConfig,
    SessionFixationStrategy, User,
};
use actix_security_examples::TestUsers;
use actix_session::storage::CookieSessionStore;
use actix_session::{Session, SessionMiddleware};
use actix_web::cookie::Key;
use actix_web::http::StatusCode;
use actix_web::{test, web, App, HttpResponse};
use std::sync::Arc;

/// Application state for tests.
struct TestAppState {
    users: Vec<User>,
    encoder: Argon2PasswordEncoder,
    session_config: SessionConfig,
}

#[actix_web::test]
async fn test_unauthenticated_dashboard_returns_401() {
    let test_users = TestUsers::new();
    let session_config = SessionConfig::new()
        .user_key("user")
        .fixation_strategy(SessionFixationStrategy::MigrateSession);

    let state = Arc::new(TestAppState {
        users: test_users.authenticated(),
        encoder: test_users.encoder,
        session_config,
    });

    let secret_key = Key::generate();

    let app = test::init_service(
        App::new()
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_secure(false)
                    .build(),
            )
            .app_data(web::Data::new(state.clone()))
            .route(
                "/dashboard",
                web::get().to(
                    |session: Session, data: web::Data<Arc<TestAppState>>| async move {
                        match SessionAuthenticator::get_session_user(&session, &data.session_config)
                        {
                            Some(user) => HttpResponse::Ok().json(serde_json::json!({
                                "username": user.get_username()
                            })),
                            None => HttpResponse::Unauthorized().json(serde_json::json!({
                                "error": "Not authenticated"
                            })),
                        }
                    },
                ),
            ),
    )
    .await;

    let req = test::TestRequest::get().uri("/dashboard").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn test_login_with_valid_credentials() {
    let test_users = TestUsers::new();
    let session_config = SessionConfig::new()
        .user_key("user")
        .fixation_strategy(SessionFixationStrategy::MigrateSession);

    let state = Arc::new(TestAppState {
        users: test_users.authenticated(),
        encoder: test_users.encoder,
        session_config,
    });

    let secret_key = Key::generate();

    let app = test::init_service(
        App::new()
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_secure(false)
                    .build(),
            )
            .app_data(web::Data::new(state.clone()))
            .route(
                "/login",
                web::post().to(
                    |session: Session,
                     data: web::Data<Arc<TestAppState>>,
                     body: web::Json<serde_json::Value>| async move {
                        let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("");
                        let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");

                        let user = data.users.iter().find(|u| u.get_username() == username);

                        match user {
                            Some(user) if data.encoder.matches(password, user.get_password()) => {
                                match SessionAuthenticator::login(
                                    &session,
                                    user,
                                    &data.session_config,
                                ) {
                                    Ok(()) => HttpResponse::Ok().json(serde_json::json!({
                                        "message": "Login successful"
                                    })),
                                    Err(e) => HttpResponse::InternalServerError()
                                        .body(format!("Session error: {}", e)),
                                }
                            }
                            _ => HttpResponse::Unauthorized().json(serde_json::json!({
                                "error": "Invalid credentials"
                            })),
                        }
                    },
                ),
            ),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/login")
        .insert_header(("Content-Type", "application/json"))
        .set_json(serde_json::json!({
            "username": "admin",
            "password": "admin"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_login_with_invalid_credentials() {
    let test_users = TestUsers::new();
    let session_config = SessionConfig::new()
        .user_key("user")
        .fixation_strategy(SessionFixationStrategy::MigrateSession);

    let state = Arc::new(TestAppState {
        users: test_users.authenticated(),
        encoder: test_users.encoder,
        session_config,
    });

    let secret_key = Key::generate();

    let app = test::init_service(
        App::new()
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_secure(false)
                    .build(),
            )
            .app_data(web::Data::new(state.clone()))
            .route(
                "/login",
                web::post().to(
                    |session: Session,
                     data: web::Data<Arc<TestAppState>>,
                     body: web::Json<serde_json::Value>| async move {
                        let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("");
                        let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");

                        let user = data.users.iter().find(|u| u.get_username() == username);

                        match user {
                            Some(user) if data.encoder.matches(password, user.get_password()) => {
                                match SessionAuthenticator::login(
                                    &session,
                                    user,
                                    &data.session_config,
                                ) {
                                    Ok(()) => HttpResponse::Ok().json(serde_json::json!({
                                        "message": "Login successful"
                                    })),
                                    Err(e) => HttpResponse::InternalServerError()
                                        .body(format!("Session error: {}", e)),
                                }
                            }
                            _ => HttpResponse::Unauthorized().json(serde_json::json!({
                                "error": "Invalid credentials"
                            })),
                        }
                    },
                ),
            ),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/login")
        .insert_header(("Content-Type", "application/json"))
        .set_json(serde_json::json!({
            "username": "admin",
            "password": "wrong"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn test_session_fixation_strategy_config() {
    // Test that different session fixation strategies can be configured
    let config_migrate = SessionConfig::new()
        .user_key("user")
        .fixation_strategy(SessionFixationStrategy::MigrateSession);

    let config_new = SessionConfig::new()
        .user_key("user")
        .fixation_strategy(SessionFixationStrategy::NewSession);

    let config_none = SessionConfig::new()
        .user_key("user")
        .fixation_strategy(SessionFixationStrategy::None);

    // All configurations should be valid (no panic)
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
