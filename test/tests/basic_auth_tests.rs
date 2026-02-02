//! HTTP Basic Authentication tests.
//!
//! Tests for RFC 7617 HTTP Basic Authentication implementation.

mod common;

use actix_web::http::StatusCode;
use actix_web::test;

use common::{basic_auth, create_test_app};

#[actix_web::test]
async fn test_basic_auth_success() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = test::read_body(resp).await;
    assert!(String::from_utf8_lossy(&body).contains("Welcome, admin!"));
}

#[actix_web::test]
async fn test_basic_auth_wrong_password() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/")
        .insert_header(("Authorization", basic_auth("admin", "wrongpassword")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn test_basic_auth_unknown_user() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/")
        .insert_header(("Authorization", basic_auth("unknown", "password")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn test_no_auth_returns_401() {
    let app = create_test_app().await;

    let req = test::TestRequest::get().uri("/").to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn test_login_page_accessible_without_auth() {
    let app = create_test_app().await;

    let req = test::TestRequest::get().uri("/login").to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}
