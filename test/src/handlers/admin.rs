//! Admin routes (protected by middleware via RequestMatcherAuthorizer).

use actix_web::{get, HttpResponse, Responder};

use actix_security::http::security::AuthenticatedUser;

/// Admin-only endpoint (requires ADMIN role - protected by middleware).
#[get("/admin/dashboard")]
pub async fn admin_dashboard(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Admin Dashboard\n\nWelcome, {}!\nYou have admin access.",
        user.get_username()
    ))
}

/// Admin users management (protected by middleware).
#[get("/admin/users")]
pub async fn admin_users(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "User Management (Admin)\n\nLogged in as: {}\nThis page is only for ADMIN role.",
        user.get_username()
    ))
}

/// User area (requires USER or ADMIN role - protected by middleware).
#[get("/user/settings")]
pub async fn user_settings(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "User Settings\n\nUser: {}\nRoles: {:?}",
        user.get_username(),
        user.get_roles()
    ))
}
