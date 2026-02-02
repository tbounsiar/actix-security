//! Custom expression tests with parameter references.
//!
//! Tests for Spring Security-like custom expressions:
//! - #[pre_authorize("custom_fn(#param)")]
//! - Parameter references from Path, Query, etc.

mod common;

use actix_web::http::StatusCode;
use actix_web::test;

use common::{basic_auth, create_test_app};

// =============================================================================
// is_tenant_admin Custom Function Tests
// =============================================================================

#[actix_web::test]
async fn test_custom_fn_tenant_admin_as_admin() {
    let app = create_test_app().await;

    // Admin can access any tenant
    let req = test::TestRequest::get()
        .uri("/tenants/123")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_custom_fn_tenant_admin_user_own_tenant() {
    let app = create_test_app().await;

    // User can access their own tenant (tenant_id == 1)
    let req = test::TestRequest::get()
        .uri("/tenants/1")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_custom_fn_tenant_admin_user_other_tenant_forbidden() {
    let app = create_test_app().await;

    // User cannot access other tenants
    let req = test::TestRequest::get()
        .uri("/tenants/2")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn test_custom_fn_tenant_admin_guest_forbidden() {
    let app = create_test_app().await;

    // Guest cannot access any tenant
    let req = test::TestRequest::get()
        .uri("/tenants/1")
        .insert_header(("Authorization", basic_auth("guest", "guest")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// =============================================================================
// Combined Built-in + Custom Function Tests
// =============================================================================

#[actix_web::test]
async fn test_combined_expr_admin_role() {
    let app = create_test_app().await;

    // hasRole('ADMIN') OR is_tenant_admin(#tenant_id)
    // Admin passes via hasRole('ADMIN')
    let req = test::TestRequest::get()
        .uri("/tenants/999/settings")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_combined_expr_tenant_admin() {
    let app = create_test_app().await;

    // hasRole('ADMIN') OR is_tenant_admin(#tenant_id)
    // User passes via is_tenant_admin for tenant 1
    let req = test::TestRequest::get()
        .uri("/tenants/1/settings")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_combined_expr_neither_forbidden() {
    let app = create_test_app().await;

    // hasRole('ADMIN') OR is_tenant_admin(#tenant_id)
    // User is neither ADMIN nor tenant admin of tenant 2
    let req = test::TestRequest::get()
        .uri("/tenants/2/settings")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// =============================================================================
// can_access_resource Custom Function Tests (String param)
// =============================================================================

#[actix_web::test]
async fn test_custom_fn_resource_admin() {
    let app = create_test_app().await;

    // Admin can access any resource
    let req = test::TestRequest::get()
        .uri("/resources/private-doc")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_custom_fn_resource_user_public() {
    let app = create_test_app().await;

    // User can access public resources
    let req = test::TestRequest::get()
        .uri("/resources/public-doc")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_custom_fn_resource_user_private_forbidden() {
    let app = create_test_app().await;

    // User cannot access private resources
    let req = test::TestRequest::get()
        .uri("/resources/private-doc")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// =============================================================================
// Query Parameter Custom Function Tests
// =============================================================================

#[actix_web::test]
async fn test_custom_fn_query_admin() {
    let app = create_test_app().await;

    // Admin can search with any min_price
    let req = test::TestRequest::get()
        .uri("/products/search?min_price=500")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_custom_fn_query_user_allowed() {
    let app = create_test_app().await;

    // Regular user can search with min_price <= 100
    let req = test::TestRequest::get()
        .uri("/products/search?min_price=50")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_custom_fn_query_user_forbidden() {
    let app = create_test_app().await;

    // Regular user cannot search with min_price > 100
    let req = test::TestRequest::get()
        .uri("/products/search?min_price=500")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn test_custom_fn_query_premium_user() {
    let app = create_test_app().await;

    // Premium user can search with any min_price (has premium:access authority)
    let req = test::TestRequest::get()
        .uri("/products/search?min_price=500")
        .insert_header(("Authorization", basic_auth("premium", "premium")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_combined_query_admin_role() {
    let app = create_test_app().await;

    // hasRole('ADMIN') OR can_search_premium(#query)
    // Admin passes via role
    let req = test::TestRequest::get()
        .uri("/products/premium-search?min_price=1000")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_combined_query_user_custom_fn() {
    let app = create_test_app().await;

    // hasRole('ADMIN') OR can_search_premium(#query)
    // User passes via custom function (min_price <= 100)
    let req = test::TestRequest::get()
        .uri("/products/premium-search?min_price=50")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// =============================================================================
// Json Body Custom Function Tests
// =============================================================================

#[actix_web::test]
async fn test_custom_fn_json_admin() {
    let app = create_test_app().await;

    // Admin can create orders of any amount
    let req = test::TestRequest::post()
        .uri("/orders")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .insert_header(("Content-Type", "application/json"))
        .set_payload(r#"{"amount": 5000}"#)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[actix_web::test]
async fn test_custom_fn_json_user_allowed() {
    let app = create_test_app().await;

    // Regular user can create orders with amount <= 1000
    let req = test::TestRequest::post()
        .uri("/orders")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .insert_header(("Content-Type", "application/json"))
        .set_payload(r#"{"amount": 500}"#)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[actix_web::test]
async fn test_custom_fn_json_user_forbidden() {
    let app = create_test_app().await;

    // Regular user cannot create orders with amount > 1000
    let req = test::TestRequest::post()
        .uri("/orders")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .insert_header(("Content-Type", "application/json"))
        .set_payload(r#"{"amount": 5000}"#)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn test_combined_json_admin_role() {
    let app = create_test_app().await;

    // hasRole('ADMIN') OR can_create_order(#body)
    // Admin passes via role
    let req = test::TestRequest::post()
        .uri("/orders/bulk")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .insert_header(("Content-Type", "application/json"))
        .set_payload(r#"{"amount": 10000}"#)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[actix_web::test]
async fn test_combined_json_user_custom_fn() {
    let app = create_test_app().await;

    // hasRole('ADMIN') OR can_create_order(#body)
    // User passes via custom function (amount <= 1000)
    let req = test::TestRequest::post()
        .uri("/orders/bulk")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .insert_header(("Content-Type", "application/json"))
        .set_payload(r#"{"amount": 500}"#)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[actix_web::test]
async fn test_combined_json_user_forbidden() {
    let app = create_test_app().await;

    // hasRole('ADMIN') OR can_create_order(#body)
    // User fails both: not ADMIN and amount > 1000
    let req = test::TestRequest::post()
        .uri("/orders/bulk")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .insert_header(("Content-Type", "application/json"))
        .set_payload(r#"{"amount": 5000}"#)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
