//! Middleware Authorization tests.
//!
//! Tests for URL pattern-based authorization via RequestMatcherAuthorizer.

mod common;

use actix_web::http::StatusCode;
use actix_web::test;

use common::{basic_auth, create_test_app};

// =============================================================================
// Admin Route Tests
// =============================================================================

#[actix_web::test]
async fn test_middleware_admin_route_with_admin() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/admin/dashboard")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = test::read_body(resp).await;
    assert!(String::from_utf8_lossy(&body).contains("Admin: admin"));
}

#[actix_web::test]
async fn test_middleware_admin_route_with_user_forbidden() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/admin/dashboard")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// =============================================================================
// User Route Tests
// =============================================================================

#[actix_web::test]
async fn test_middleware_user_route_with_user() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/user/settings")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_middleware_user_route_with_guest_forbidden() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/user/settings")
        .insert_header(("Authorization", basic_auth("guest", "guest")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// =============================================================================
// API Route Tests (Authority-based)
// =============================================================================

#[actix_web::test]
async fn test_middleware_api_route_with_authority() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/api/users")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_middleware_api_route_without_authority_forbidden() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/api/users")
        .insert_header(("Authorization", basic_auth("guest", "guest")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
