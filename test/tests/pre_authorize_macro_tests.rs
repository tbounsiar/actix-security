//! #[pre_authorize] Macro tests.
//!
//! Tests for the @PreAuthorize equivalent macro.

mod common;

use actix_web::http::StatusCode;
use actix_web::test;

use common::{basic_auth, create_test_app};

// =============================================================================
// Authority Tests
// =============================================================================

#[actix_web::test]
async fn test_pre_authorize_authority_with_write() {
    let app = create_test_app().await;

    // Admin has users:write authority
    let req = test::TestRequest::post()
        .uri("/preauth/write")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_pre_authorize_authority_without_write_forbidden() {
    let app = create_test_app().await;

    // User only has users:read, not users:write
    let req = test::TestRequest::post()
        .uri("/preauth/write")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// =============================================================================
// Authorities Array Tests
// =============================================================================

#[actix_web::test]
async fn test_pre_authorize_authorities_array_with_read() {
    let app = create_test_app().await;

    // User has users:read, which is in ["users:read", "users:write"]
    let req = test::TestRequest::get()
        .uri("/preauth/read-or-write")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_pre_authorize_authorities_array_without_any_forbidden() {
    let app = create_test_app().await;

    // Guest has no authorities
    let req = test::TestRequest::get()
        .uri("/preauth/read-or-write")
        .insert_header(("Authorization", basic_auth("guest", "guest")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// =============================================================================
// Role Tests
// =============================================================================

#[actix_web::test]
async fn test_pre_authorize_role_with_user() {
    let app = create_test_app().await;

    // User has USER role
    let req = test::TestRequest::get()
        .uri("/preauth/user-role")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_pre_authorize_role_with_admin() {
    let app = create_test_app().await;

    // Admin also has USER role
    let req = test::TestRequest::get()
        .uri("/preauth/user-role")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_pre_authorize_role_with_guest_forbidden() {
    let app = create_test_app().await;

    // Guest has GUEST role, not USER
    let req = test::TestRequest::get()
        .uri("/preauth/user-role")
        .insert_header(("Authorization", basic_auth("guest", "guest")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// =============================================================================
// Authenticated Tests
// =============================================================================

#[actix_web::test]
async fn test_pre_authorize_authenticated_with_any_user() {
    let app = create_test_app().await;

    // Any authenticated user should pass
    let req = test::TestRequest::get()
        .uri("/preauth/authenticated")
        .insert_header(("Authorization", basic_auth("guest", "guest")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}
