//! #[secured] Macro tests.
//!
//! Tests for the @Secured equivalent macro.

mod common;

use actix_web::http::StatusCode;
use actix_web::test;

use common::{basic_auth, create_test_app};

#[actix_web::test]
async fn test_secured_admin_with_admin() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/secured/admin")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = test::read_body(resp).await;
    assert!(String::from_utf8_lossy(&body).contains("Secured Admin: admin"));
}

#[actix_web::test]
async fn test_secured_admin_with_user_forbidden() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/secured/admin")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn test_secured_multiple_roles_with_admin() {
    let app = create_test_app().await;

    // Admin has ADMIN role, so should pass #[secured("ADMIN", "MANAGER")]
    let req = test::TestRequest::get()
        .uri("/secured/management")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_secured_multiple_roles_with_user_forbidden() {
    let app = create_test_app().await;

    // User has USER role, not ADMIN or MANAGER
    let req = test::TestRequest::get()
        .uri("/secured/management")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
