//! Security Headers Example
//!
//! This example demonstrates how to add security headers to responses.
//!
//! # Run
//! ```bash
//! cargo run --example security_headers
//! ```
//!
//! # Test
//! ```bash
//! # Check headers
//! curl -v http://localhost:8080/ 2>&1 | grep -i "x-\|content-security\|strict-transport"
//!
//! # Response will include:
//! # X-Frame-Options: DENY
//! # X-Content-Type-Options: nosniff
//! # X-XSS-Protection: 1; mode=block
//! # Content-Security-Policy: default-src 'self'
//! # Strict-Transport-Security: max-age=31536000; includeSubDomains
//! ```

use actix_security::http::security::SecurityHeaders;
use actix_web::{get, App, HttpResponse, HttpServer, Responder};

/// Home page
#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Security Headers Example",
        "note": "Check response headers with: curl -v http://localhost:8080/"
    }))
}

/// API endpoint
#[get("/api/data")]
async fn api_data() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "data": [1, 2, 3, 4, 5],
        "secure": true
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    println!("=== Security Headers Example ===");
    println!("Server running at http://localhost:8080");
    println!();
    println!("Security headers applied:");
    println!("  X-Frame-Options: DENY");
    println!("  X-Content-Type-Options: nosniff");
    println!("  X-XSS-Protection: 1; mode=block");
    println!("  Content-Security-Policy: default-src 'self'; script-src 'self'");
    println!("  Strict-Transport-Security: max-age=31536000; includeSubDomains");
    println!("  Referrer-Policy: strict-origin-when-cross-origin");
    println!("  Permissions-Policy: geolocation=(), camera=(), microphone=()");
    println!();
    println!("Try:");
    println!("  curl -v http://localhost:8080/ 2>&1 | grep -E '^< '");
    println!();

    HttpServer::new(|| {
        App::new()
            // Apply strict security headers
            .wrap(
                SecurityHeaders::strict()
                    // Customize CSP for your application
                    .content_security_policy("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")
                    // Add permissions policy
                    .permissions_policy("geolocation=(), camera=(), microphone=()")
            )
            .service(index)
            .service(api_data)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
