//! Simple macro tests: permit_all, deny_all, roles_allowed.
//!
//! Tests for Java EE-style security annotations.

mod common;

use actix_web::http::StatusCode;
use actix_web::test;

use common::{basic_auth, create_test_app};

// =============================================================================
// permit_all Tests
// =============================================================================

#[actix_web::test]
async fn test_permit_all_without_auth() {
    let app = create_test_app().await;

    // Public endpoint - no auth required
    let req = test::TestRequest::get().uri("/public/info").to_request();

    let resp = test::call_service(&app, req).await;
    // Note: The middleware still requires auth for all routes in this test setup
    // permit_all just means the handler doesn't check permissions
    // In a real app, you'd configure the authorizer to skip this path
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn test_permit_all_with_any_user() {
    let app = create_test_app().await;

    // Even guest can access permit_all endpoint
    let req = test::TestRequest::get()
        .uri("/public/info")
        .insert_header(("Authorization", basic_auth("guest", "guest")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// =============================================================================
// deny_all Tests
// =============================================================================

#[actix_web::test]
async fn test_deny_all_with_admin() {
    let app = create_test_app().await;

    // Even admin is denied
    let req = test::TestRequest::get()
        .uri("/disabled")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn test_deny_all_with_user() {
    let app = create_test_app().await;

    // User is also denied
    let req = test::TestRequest::get()
        .uri("/disabled")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// =============================================================================
// roles_allowed Tests (Java EE style)
// =============================================================================

#[actix_web::test]
async fn test_roles_allowed_with_admin() {
    let app = create_test_app().await;

    // Admin has ADMIN role
    let req = test::TestRequest::get()
        .uri("/javaee/admin")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_roles_allowed_with_user_forbidden() {
    let app = create_test_app().await;

    // User doesn't have ADMIN role
    let req = test::TestRequest::get()
        .uri("/javaee/admin")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn test_roles_allowed_multiple_with_admin() {
    let app = create_test_app().await;

    // Admin has ADMIN role (one of ADMIN, MANAGER)
    let req = test::TestRequest::get()
        .uri("/javaee/management")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_roles_allowed_multiple_with_user_forbidden() {
    let app = create_test_app().await;

    // User doesn't have ADMIN or MANAGER role
    let req = test::TestRequest::get()
        .uri("/javaee/management")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
