//! Security headers middleware tests.
//!
//! Tests for HTTP security headers (X-Frame-Options, CSP, HSTS, etc.)

use actix_web::http::StatusCode;
use actix_web::{get, test, App, HttpResponse, Responder};

use actix_security_core::http::security::headers::{FrameOptions, ReferrerPolicy, SecurityHeaders};

#[get("/test")]
async fn test_endpoint() -> impl Responder {
    HttpResponse::Ok().body("Test")
}

// =============================================================================
// Default Headers Tests
// =============================================================================

#[actix_web::test]
async fn test_default_security_headers() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeaders::default())
            .service(test_endpoint),
    )
    .await;

    let req = test::TestRequest::get().uri("/test").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);

    let headers = resp.headers();

    // X-Content-Type-Options should be set
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");

    // X-Frame-Options should be DENY by default
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");

    // X-XSS-Protection should be 0 (disabled)
    assert_eq!(headers.get("x-xss-protection").unwrap(), "0");

    // Referrer-Policy should be set
    assert_eq!(
        headers.get("referrer-policy").unwrap(),
        "strict-origin-when-cross-origin"
    );
}

// =============================================================================
// Custom Configuration Tests
// =============================================================================

#[actix_web::test]
async fn test_frame_options_sameorigin() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeaders::new().frame_options(FrameOptions::SameOrigin))
            .service(test_endpoint),
    )
    .await;

    let req = test::TestRequest::get().uri("/test").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.headers().get("x-frame-options").unwrap(), "SAMEORIGIN");
}

#[actix_web::test]
async fn test_frame_options_disabled() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeaders::new().frame_options(FrameOptions::Disabled))
            .service(test_endpoint),
    )
    .await;

    let req = test::TestRequest::get().uri("/test").to_request();
    let resp = test::call_service(&app, req).await;

    // X-Frame-Options should not be present
    assert!(resp.headers().get("x-frame-options").is_none());
}

#[actix_web::test]
async fn test_content_security_policy() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeaders::new().content_security_policy("default-src 'self'"))
            .service(test_endpoint),
    )
    .await;

    let req = test::TestRequest::get().uri("/test").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(
        resp.headers().get("content-security-policy").unwrap(),
        "default-src 'self'"
    );
}

#[actix_web::test]
async fn test_hsts_enabled() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeaders::new().hsts(true, 31536000))
            .service(test_endpoint),
    )
    .await;

    let req = test::TestRequest::get().uri("/test").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(
        resp.headers().get("strict-transport-security").unwrap(),
        "max-age=31536000"
    );
}

#[actix_web::test]
async fn test_hsts_with_subdomains() {
    let app = test::init_service(
        App::new()
            .wrap(
                SecurityHeaders::new()
                    .hsts(true, 31536000)
                    .hsts_include_subdomains(true),
            )
            .service(test_endpoint),
    )
    .await;

    let req = test::TestRequest::get().uri("/test").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(
        resp.headers().get("strict-transport-security").unwrap(),
        "max-age=31536000; includeSubDomains"
    );
}

#[actix_web::test]
async fn test_hsts_with_preload() {
    let app = test::init_service(
        App::new()
            .wrap(
                SecurityHeaders::new()
                    .hsts(true, 31536000)
                    .hsts_include_subdomains(true)
                    .hsts_preload(true),
            )
            .service(test_endpoint),
    )
    .await;

    let req = test::TestRequest::get().uri("/test").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(
        resp.headers().get("strict-transport-security").unwrap(),
        "max-age=31536000; includeSubDomains; preload"
    );
}

#[actix_web::test]
async fn test_referrer_policy_no_referrer() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeaders::new().referrer_policy(ReferrerPolicy::NoReferrer))
            .service(test_endpoint),
    )
    .await;

    let req = test::TestRequest::get().uri("/test").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(
        resp.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );
}

#[actix_web::test]
async fn test_permissions_policy() {
    let app = test::init_service(
        App::new()
            .wrap(
                SecurityHeaders::new()
                    .permissions_policy("geolocation=(), microphone=(), camera=()"),
            )
            .service(test_endpoint),
    )
    .await;

    let req = test::TestRequest::get().uri("/test").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(
        resp.headers().get("permissions-policy").unwrap(),
        "geolocation=(), microphone=(), camera=()"
    );
}

#[actix_web::test]
async fn test_cache_control() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeaders::new().cache_control("no-cache, no-store, must-revalidate"))
            .service(test_endpoint),
    )
    .await;

    let req = test::TestRequest::get().uri("/test").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "no-cache, no-store, must-revalidate"
    );
}

// =============================================================================
// Strict Configuration Tests
// =============================================================================

#[actix_web::test]
async fn test_strict_security_headers() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeaders::strict())
            .service(test_endpoint),
    )
    .await;

    let req = test::TestRequest::get().uri("/test").to_request();
    let resp = test::call_service(&app, req).await;

    let headers = resp.headers();

    // All headers should be set
    assert!(headers.get("x-content-type-options").is_some());
    assert!(headers.get("x-frame-options").is_some());
    assert!(headers.get("content-security-policy").is_some());
    assert!(headers.get("strict-transport-security").is_some());
    assert!(headers.get("referrer-policy").is_some());
    assert!(headers.get("permissions-policy").is_some());
    assert!(headers.get("cache-control").is_some());

    // Verify strict values
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(
        headers.get("content-security-policy").unwrap(),
        "default-src 'self'"
    );
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
}
