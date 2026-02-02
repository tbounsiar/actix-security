//! Expression-based authorization tests.
//!
//! Tests for Spring Security-like SpEL expressions:
//! - #[pre_authorize("hasRole('ADMIN') OR hasAuthority('write')")]

mod common;

use actix_web::http::StatusCode;
use actix_web::test;

use common::{basic_auth, create_test_app};

// =============================================================================
// OR Expression Tests
// =============================================================================

#[actix_web::test]
async fn test_expr_or_with_admin_role() {
    let app = create_test_app().await;

    // Admin has ADMIN role, so hasRole('ADMIN') OR hasAuthority('users:write') = true
    let req = test::TestRequest::get()
        .uri("/expr/admin-or-write")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_expr_or_with_write_authority() {
    let app = create_test_app().await;

    // Admin has users:write authority
    let req = test::TestRequest::get()
        .uri("/expr/admin-or-write")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_expr_or_without_either_forbidden() {
    let app = create_test_app().await;

    // User doesn't have ADMIN role or users:write authority
    let req = test::TestRequest::get()
        .uri("/expr/admin-or-write")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// =============================================================================
// AND Expression Tests
// =============================================================================

#[actix_web::test]
async fn test_expr_and_with_both() {
    let app = create_test_app().await;

    // Admin has USER role and users:read authority
    let req = test::TestRequest::get()
        .uri("/expr/user-and-read")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_expr_and_with_user() {
    let app = create_test_app().await;

    // User has USER role and users:read authority
    let req = test::TestRequest::get()
        .uri("/expr/user-and-read")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_expr_and_without_authority_forbidden() {
    let app = create_test_app().await;

    // Guest has GUEST role, no USER role
    let req = test::TestRequest::get()
        .uri("/expr/user-and-read")
        .insert_header(("Authorization", basic_auth("guest", "guest")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// =============================================================================
// NOT Expression Tests
// =============================================================================

#[actix_web::test]
async fn test_expr_not_guest_with_admin() {
    let app = create_test_app().await;

    // Admin is NOT GUEST
    let req = test::TestRequest::get()
        .uri("/expr/not-guest")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_expr_not_guest_with_user() {
    let app = create_test_app().await;

    // User is NOT GUEST
    let req = test::TestRequest::get()
        .uri("/expr/not-guest")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_expr_not_guest_with_guest_forbidden() {
    let app = create_test_app().await;

    // Guest IS GUEST, so NOT hasRole('GUEST') = false
    let req = test::TestRequest::get()
        .uri("/expr/not-guest")
        .insert_header(("Authorization", basic_auth("guest", "guest")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// =============================================================================
// Complex Expression Tests
// =============================================================================

#[actix_web::test]
async fn test_expr_complex_with_admin() {
    let app = create_test_app().await;

    // Admin has ADMIN role (matches first part of OR) AND has users:read
    let req = test::TestRequest::get()
        .uri("/expr/complex")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_expr_complex_with_user() {
    let app = create_test_app().await;

    // User has USER role (matches second part of OR) AND has users:read
    let req = test::TestRequest::get()
        .uri("/expr/complex")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_expr_complex_with_guest_forbidden() {
    let app = create_test_app().await;

    // Guest has neither ADMIN nor USER role, and no users:read authority
    let req = test::TestRequest::get()
        .uri("/expr/complex")
        .insert_header(("Authorization", basic_auth("guest", "guest")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// =============================================================================
// hasAnyRole Tests
// =============================================================================

#[actix_web::test]
async fn test_expr_any_role_with_admin() {
    let app = create_test_app().await;

    // Admin has ADMIN role (in ['ADMIN', 'MANAGER'])
    let req = test::TestRequest::get()
        .uri("/expr/any-role")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_expr_any_role_with_user_forbidden() {
    let app = create_test_app().await;

    // User has USER role, not ADMIN or MANAGER
    let req = test::TestRequest::get()
        .uri("/expr/any-role")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// =============================================================================
// hasAnyAuthority Tests
// =============================================================================

#[actix_web::test]
async fn test_expr_any_authority_with_read() {
    let app = create_test_app().await;

    // User has users:read authority
    let req = test::TestRequest::get()
        .uri("/expr/any-authority")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_expr_any_authority_with_write() {
    let app = create_test_app().await;

    // Admin has both users:read and users:write
    let req = test::TestRequest::get()
        .uri("/expr/any-authority")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_expr_any_authority_without_forbidden() {
    let app = create_test_app().await;

    // Guest has no authorities
    let req = test::TestRequest::get()
        .uri("/expr/any-authority")
        .insert_header(("Authorization", basic_auth("guest", "guest")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// =============================================================================
// isAuthenticated Tests
// =============================================================================

#[actix_web::test]
async fn test_expr_authenticated_with_any_user() {
    let app = create_test_app().await;

    // Any authenticated user should pass
    let req = test::TestRequest::get()
        .uri("/expr/authenticated")
        .insert_header(("Authorization", basic_auth("guest", "guest")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// =============================================================================
// permitAll / denyAll Tests
// =============================================================================

#[actix_web::test]
async fn test_expr_permit_all() {
    let app = create_test_app().await;

    // permitAll() always returns true
    let req = test::TestRequest::get()
        .uri("/expr/permit-all")
        .insert_header(("Authorization", basic_auth("guest", "guest")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_expr_deny_all() {
    let app = create_test_app().await;

    // denyAll() always returns false
    let req = test::TestRequest::get()
        .uri("/expr/deny-all")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
