//! Integration tests for the basic_auth example.
//!
//! These tests verify HTTP Basic authentication and role-based access control.

use actix_security::http::security::web::{Access, MemoryAuthenticator, RequestMatcherAuthorizer};
use actix_security::http::security::{
    middleware::SecurityTransform, Argon2PasswordEncoder, AuthenticationManager,
    AuthorizationManager, PasswordEncoder, User,
};
use actix_security_examples::{credentials, server};
use actix_web::{test, web, App, HttpResponse};

/// Creates the authenticator for tests.
fn create_authenticator() -> MemoryAuthenticator {
    let encoder = Argon2PasswordEncoder::new();

    AuthenticationManager::in_memory_authentication()
        .password_encoder(encoder.clone())
        .with_user(
            User::with_encoded_password("admin", encoder.encode("admin"))
                .roles(&["ADMIN".into(), "USER".into()])
                .authorities(&["users:read".into(), "users:write".into()]),
        )
        .with_user(
            User::with_encoded_password("user", encoder.encode("user"))
                .roles(&["USER".into()])
                .authorities(&["users:read".into()]),
        )
}

/// Creates the authorizer for tests.
fn create_authorizer() -> RequestMatcherAuthorizer {
    AuthorizationManager::request_matcher()
        .http_basic()
        .add_matcher("/admin.*", Access::new().roles(vec!["ADMIN"]))
        .add_matcher("/api/.*", Access::new().authorities(vec!["users:read"]))
}

#[actix_web::test]
async fn test_unauthenticated_request_returns_401() {
    let app = test::init_service(
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(create_authenticator)
                    .config_authorizer(create_authorizer),
            )
            .route(
                "/",
                web::get().to(|| async { HttpResponse::Ok().body("Hello") }),
            ),
    )
    .await;

    let req = test::TestRequest::get().uri("/").to_request();
    let resp = test::call_service(&app, req).await;

    server::assert_unauthorized(&resp);
}

#[actix_web::test]
async fn test_admin_can_access_root() {
    let app = test::init_service(
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(create_authenticator)
                    .config_authorizer(create_authorizer),
            )
            .route(
                "/",
                web::get().to(|| async { HttpResponse::Ok().body("Hello") }),
            ),
    )
    .await;

    let (username, password) = credentials::admin();
    let req = test::TestRequest::get()
        .uri("/")
        .insert_header(("Authorization", credentials::basic_auth(username, password)))
        .to_request();
    let resp = test::call_service(&app, req).await;

    server::assert_ok(&resp);
}

#[actix_web::test]
async fn test_user_can_access_root() {
    let app = test::init_service(
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(create_authenticator)
                    .config_authorizer(create_authorizer),
            )
            .route(
                "/",
                web::get().to(|| async { HttpResponse::Ok().body("Hello") }),
            ),
    )
    .await;

    let (username, password) = credentials::user();
    let req = test::TestRequest::get()
        .uri("/")
        .insert_header(("Authorization", credentials::basic_auth(username, password)))
        .to_request();
    let resp = test::call_service(&app, req).await;

    server::assert_ok(&resp);
}

#[actix_web::test]
async fn test_admin_can_access_admin_route() {
    let app = test::init_service(
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(create_authenticator)
                    .config_authorizer(create_authorizer),
            )
            .route(
                "/admin",
                web::get().to(|| async { HttpResponse::Ok().body("Admin panel") }),
            ),
    )
    .await;

    let (username, password) = credentials::admin();
    let req = test::TestRequest::get()
        .uri("/admin")
        .insert_header(("Authorization", credentials::basic_auth(username, password)))
        .to_request();
    let resp = test::call_service(&app, req).await;

    server::assert_ok(&resp);
}

#[actix_web::test]
async fn test_user_cannot_access_admin_route() {
    let app = test::init_service(
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(create_authenticator)
                    .config_authorizer(create_authorizer),
            )
            .route(
                "/admin",
                web::get().to(|| async { HttpResponse::Ok().body("Admin panel") }),
            ),
    )
    .await;

    let (username, password) = credentials::user();
    let req = test::TestRequest::get()
        .uri("/admin")
        .insert_header(("Authorization", credentials::basic_auth(username, password)))
        .to_request();
    let resp = test::call_service(&app, req).await;

    server::assert_forbidden(&resp);
}

#[actix_web::test]
async fn test_admin_can_access_api() {
    let app = test::init_service(
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(create_authenticator)
                    .config_authorizer(create_authorizer),
            )
            .route(
                "/api/users",
                web::get().to(|| async { HttpResponse::Ok().body("Users list") }),
            ),
    )
    .await;

    let (username, password) = credentials::admin();
    let req = test::TestRequest::get()
        .uri("/api/users")
        .insert_header(("Authorization", credentials::basic_auth(username, password)))
        .to_request();
    let resp = test::call_service(&app, req).await;

    server::assert_ok(&resp);
}

#[actix_web::test]
async fn test_user_can_access_api() {
    let app = test::init_service(
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(create_authenticator)
                    .config_authorizer(create_authorizer),
            )
            .route(
                "/api/users",
                web::get().to(|| async { HttpResponse::Ok().body("Users list") }),
            ),
    )
    .await;

    let (username, password) = credentials::user();
    let req = test::TestRequest::get()
        .uri("/api/users")
        .insert_header(("Authorization", credentials::basic_auth(username, password)))
        .to_request();
    let resp = test::call_service(&app, req).await;

    server::assert_ok(&resp);
}

#[actix_web::test]
async fn test_invalid_credentials_returns_401() {
    let app = test::init_service(
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(create_authenticator)
                    .config_authorizer(create_authorizer),
            )
            .route(
                "/",
                web::get().to(|| async { HttpResponse::Ok().body("Hello") }),
            ),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/")
        .insert_header(("Authorization", credentials::basic_auth("admin", "wrong")))
        .to_request();
    let resp = test::call_service(&app, req).await;

    server::assert_unauthorized(&resp);
}

#[actix_web::test]
async fn test_malformed_auth_header_returns_401() {
    let app = test::init_service(
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(create_authenticator)
                    .config_authorizer(create_authorizer),
            )
            .route(
                "/",
                web::get().to(|| async { HttpResponse::Ok().body("Hello") }),
            ),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/")
        .insert_header(("Authorization", "InvalidHeader"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    server::assert_unauthorized(&resp);
}
