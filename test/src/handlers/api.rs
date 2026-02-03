//! API routes (protected by middleware and/or macros).

use actix_web::{get, HttpResponse, Responder};

use actix_security::http::security::AuthenticatedUser;

/// API endpoint protected by authority (middleware level).
#[get("/api/users")]
pub async fn api_users(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/json")
        .body(format!(
            r#"{{"message": "User list", "requestedBy": "{}"}}"#,
            user.get_username()
        ))
}
