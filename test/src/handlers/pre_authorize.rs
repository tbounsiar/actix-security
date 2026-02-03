//! Routes protected by #[pre_authorize] macro.
//!
//! # Spring Security Equivalent
//! `@PreAuthorize` annotation

use actix_web::{get, post, HttpResponse, Responder};

use actix_security::http::security::AuthenticatedUser;
use actix_security::pre_authorize;

/// Write endpoint - protected by #[pre_authorize] macro (authority-based).
///
/// # Spring Security Equivalent
/// `@PreAuthorize("hasAuthority('users:write')")`
#[pre_authorize(authority = "users:write")]
#[post("/api/users/create")]
pub async fn create_user(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/json")
        .body(format!(
            r#"{{"message": "User created", "createdBy": "{}", "note": "This endpoint uses #[pre_authorize(authority = \"users:write\")]"}}"#,
            user.get_username()
        ))
}

/// Stats endpoint - requires read OR write authority.
///
/// # Spring Security Equivalent
/// `@PreAuthorize("hasAnyAuthority('users:read', 'users:write')")`
#[pre_authorize(authorities = ["users:read", "users:write"])]
#[get("/api/stats")]
pub async fn api_stats(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/json")
        .body(format!(
            r#"{{"stats": {{"users": 100, "active": 42}}, "requestedBy": "{}"}}"#,
            user.get_username()
        ))
}

/// Protected endpoint - demonstrates #[pre_authorize(authenticated)].
///
/// # Spring Security Equivalent
/// `@PreAuthorize("isAuthenticated()")`
#[pre_authorize(authenticated)]
#[get("/protected")]
pub async fn protected_resource(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Protected Resource\n\nYou are authenticated as: {}\nThis uses #[pre_authorize(authenticated)]",
        user.get_username()
    ))
}

/// Role-based with pre_authorize - demonstrates role check syntax.
///
/// # Spring Security Equivalent
/// `@PreAuthorize("hasRole('USER')")`
#[pre_authorize(role = "USER")]
#[get("/user-only")]
pub async fn user_only(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "User-Only Area\n\nWelcome, {}!\nThis uses #[pre_authorize(role = \"USER\")]",
        user.get_username()
    ))
}
