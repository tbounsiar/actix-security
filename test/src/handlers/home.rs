//! Home routes (authentication required via extractor).

use actix_web::{get, HttpResponse, Responder};

use actix_security::http::security::{AuthenticatedUser, OptionalUser};

/// Home page - shows current user info.
/// Uses AuthenticatedUser extractor (returns 401 if not authenticated).
#[get("/")]
pub async fn index(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Welcome, {}!\nRoles: {:?}\nAuthorities: {:?}",
        user.get_username(),
        user.get_roles(),
        user.get_authorities()
    ))
}

/// Profile page - uses OptionalUser extractor (never fails).
#[get("/profile")]
pub async fn profile(user: OptionalUser) -> impl Responder {
    match user.into_inner() {
        Some(u) => HttpResponse::Ok().body(format!(
            "Profile for: {}\nRoles: {:?}",
            u.get_username(),
            u.get_roles()
        )),
        None => HttpResponse::Ok().body("Guest profile - please login"),
    }
}
