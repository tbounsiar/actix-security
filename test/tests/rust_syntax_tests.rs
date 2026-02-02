//! Tests for Rust-style expression syntax.
//!
//! Tests for snake_case functions and Rust operators:
//! - has_role, has_any_role, has_authority, has_any_authority
//! - is_authenticated, permit_all, deny_all
//! - && (AND), || (OR), ! (NOT)

mod common;

use actix_web::http::StatusCode;
use actix_web::test;

use common::{basic_auth, create_test_app};

// =============================================================================
// Snake_case Function Tests
// =============================================================================

#[actix_web::test]
async fn test_snake_case_has_role_admin() {
    let app = create_test_app().await;

    // has_role('ADMIN') - admin should pass
    let req = test::TestRequest::get()
        .uri("/expr/snake-role")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_snake_case_has_role_user_forbidden() {
    let app = create_test_app().await;

    // has_role('ADMIN') - user should be forbidden
    let req = test::TestRequest::get()
        .uri("/expr/snake-role")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn test_snake_case_permit_all() {
    let app = create_test_app().await;

    // permit_all() - should always pass
    let req = test::TestRequest::get()
        .uri("/expr/snake-permit")
        .insert_header(("Authorization", basic_auth("guest", "guest")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_snake_case_deny_all() {
    let app = create_test_app().await;

    // deny_all() - should always fail
    let req = test::TestRequest::get()
        .uri("/expr/snake-deny")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn test_snake_case_mixed() {
    let app = create_test_app().await;

    // has_any_role('ADMIN', 'USER') && is_authenticated() - user should pass
    let req = test::TestRequest::get()
        .uri("/expr/snake-mixed")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_snake_case_mixed_guest_forbidden() {
    let app = create_test_app().await;

    // has_any_role('ADMIN', 'USER') && is_authenticated() - guest should fail
    let req = test::TestRequest::get()
        .uri("/expr/snake-mixed")
        .insert_header(("Authorization", basic_auth("guest", "guest")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// =============================================================================
// Rust-style Operator Tests (&&, ||, !)
// =============================================================================

#[actix_web::test]
async fn test_rust_or_operator_admin() {
    let app = create_test_app().await;

    // has_role('ADMIN') || has_authority('users:write') - admin should pass
    let req = test::TestRequest::get()
        .uri("/expr/rust-or")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_rust_or_operator_user_forbidden() {
    let app = create_test_app().await;

    // has_role('ADMIN') || has_authority('users:write') - user doesn't have either
    let req = test::TestRequest::get()
        .uri("/expr/rust-or")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn test_rust_and_operator_user() {
    let app = create_test_app().await;

    // has_role('USER') && has_authority('users:read') - user should pass
    let req = test::TestRequest::get()
        .uri("/expr/rust-and")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_rust_and_operator_admin() {
    let app = create_test_app().await;

    // has_role('USER') && has_authority('users:read') - admin has both
    let req = test::TestRequest::get()
        .uri("/expr/rust-and")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_rust_and_operator_guest_forbidden() {
    let app = create_test_app().await;

    // has_role('USER') && has_authority('users:read') - guest has neither
    let req = test::TestRequest::get()
        .uri("/expr/rust-and")
        .insert_header(("Authorization", basic_auth("guest", "guest")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn test_rust_not_operator_admin() {
    let app = create_test_app().await;

    // !has_role('GUEST') - admin is not guest
    let req = test::TestRequest::get()
        .uri("/expr/rust-not")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_rust_not_operator_user() {
    let app = create_test_app().await;

    // !has_role('GUEST') - user is not guest
    let req = test::TestRequest::get()
        .uri("/expr/rust-not")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_rust_not_operator_guest_forbidden() {
    let app = create_test_app().await;

    // !has_role('GUEST') - guest IS a guest
    let req = test::TestRequest::get()
        .uri("/expr/rust-not")
        .insert_header(("Authorization", basic_auth("guest", "guest")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
