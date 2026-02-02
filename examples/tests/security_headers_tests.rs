//! Integration tests for the security_headers example.
//!
//! These tests verify that security headers are properly applied to responses.

use actix_security::http::security::headers::{FrameOptions, SecurityHeaders};
use actix_web::http::StatusCode;
use actix_web::{test, web, App, HttpResponse};

#[actix_web::test]
async fn test_x_frame_options_header() {
    let app = test::init_service(
        App::new()
            .wrap(
                SecurityHeaders::strict()
                    .content_security_policy("default-src 'self'")
                    .permissions_policy("geolocation=(), camera=()"),
            )
            .route("/", web::get().to(|| async { HttpResponse::Ok().body("OK") })),
    )
    .await;

    let req = test::TestRequest::get().uri("/").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let headers = resp.headers();
    assert!(headers.get("X-Frame-Options").is_some());
    assert_eq!(
        headers.get("X-Frame-Options").unwrap().to_str().unwrap(),
        "DENY"
    );
}

#[actix_web::test]
async fn test_x_content_type_options_header() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeaders::strict())
            .route("/", web::get().to(|| async { HttpResponse::Ok().body("OK") })),
    )
    .await;

    let req = test::TestRequest::get().uri("/").to_request();
    let resp = test::call_service(&app, req).await;

    let headers = resp.headers();
    assert!(headers.get("X-Content-Type-Options").is_some());
    assert_eq!(
        headers
            .get("X-Content-Type-Options")
            .unwrap()
            .to_str()
            .unwrap(),
        "nosniff"
    );
}

#[actix_web::test]
async fn test_content_security_policy_header() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeaders::strict().content_security_policy("default-src 'self'"))
            .route("/", web::get().to(|| async { HttpResponse::Ok().body("OK") })),
    )
    .await;

    let req = test::TestRequest::get().uri("/").to_request();
    let resp = test::call_service(&app, req).await;

    let headers = resp.headers();
    assert!(headers.get("Content-Security-Policy").is_some());
    assert!(headers
        .get("Content-Security-Policy")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("default-src 'self'"));
}

#[actix_web::test]
async fn test_strict_transport_security_header() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeaders::strict())
            .route("/", web::get().to(|| async { HttpResponse::Ok().body("OK") })),
    )
    .await;

    let req = test::TestRequest::get().uri("/").to_request();
    let resp = test::call_service(&app, req).await;

    let headers = resp.headers();
    assert!(headers.get("Strict-Transport-Security").is_some());
    assert!(headers
        .get("Strict-Transport-Security")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("max-age="));
}

#[actix_web::test]
async fn test_referrer_policy_header() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeaders::strict())
            .route("/", web::get().to(|| async { HttpResponse::Ok().body("OK") })),
    )
    .await;

    let req = test::TestRequest::get().uri("/").to_request();
    let resp = test::call_service(&app, req).await;

    let headers = resp.headers();
    assert!(headers.get("Referrer-Policy").is_some());
}

#[actix_web::test]
async fn test_permissions_policy_header() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeaders::strict().permissions_policy("geolocation=(), camera=()"))
            .route("/", web::get().to(|| async { HttpResponse::Ok().body("OK") })),
    )
    .await;

    let req = test::TestRequest::get().uri("/").to_request();
    let resp = test::call_service(&app, req).await;

    let headers = resp.headers();
    assert!(headers.get("Permissions-Policy").is_some());
    let policy = headers
        .get("Permissions-Policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(policy.contains("geolocation=()"));
    assert!(policy.contains("camera=()"));
}

#[actix_web::test]
async fn test_custom_frame_options() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeaders::new().frame_options(FrameOptions::SameOrigin))
            .route("/", web::get().to(|| async { HttpResponse::Ok().body("OK") })),
    )
    .await;

    let req = test::TestRequest::get().uri("/").to_request();
    let resp = test::call_service(&app, req).await;

    let headers = resp.headers();
    assert_eq!(
        headers.get("X-Frame-Options").unwrap().to_str().unwrap(),
        "SAMEORIGIN"
    );
}

#[actix_web::test]
async fn test_custom_csp() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeaders::new().content_security_policy("default-src 'none'"))
            .route("/", web::get().to(|| async { HttpResponse::Ok().body("OK") })),
    )
    .await;

    let req = test::TestRequest::get().uri("/").to_request();
    let resp = test::call_service(&app, req).await;

    let headers = resp.headers();
    assert!(headers
        .get("Content-Security-Policy")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("default-src 'none'"));
}
