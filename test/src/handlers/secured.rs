//! Routes protected by #[secured] macro.
//!
//! # Spring Security Equivalent
//! `@Secured` annotation

use actix_web::{get, HttpResponse, Responder};

use actix_security::http::security::AuthenticatedUser;
use actix_security::secured;

/// Reports page - protected by #[secured] macro (ADMIN role required).
///
/// # Spring Security Equivalent
/// `@Secured("ROLE_ADMIN")`
#[secured("ADMIN")]
#[get("/reports")]
pub async fn reports(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Reports Dashboard\n\nGenerated for: {}\nThis endpoint uses #[secured(\"ADMIN\")] macro.",
        user.get_username()
    ))
}

/// Management page - protected by #[secured] macro (ADMIN or MANAGER role).
///
/// # Spring Security Equivalent
/// `@Secured({"ROLE_ADMIN", "ROLE_MANAGER"})`
#[secured("ADMIN", "MANAGER")]
#[get("/management")]
pub async fn management(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Management Panel\n\nUser: {}\nRoles: {:?}\nThis endpoint requires ADMIN or MANAGER role.",
        user.get_username(),
        user.get_roles()
    ))
}
