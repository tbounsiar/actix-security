//! Public routes (no authentication required).

use actix_web::{get, post, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct LoginForm {
    pub user_name: String,
    pub password: String,
}

#[get("/login")]
pub async fn login() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../../web/login.html"))
}

#[post("/login")]
pub async fn post_login(login_form: web::Form<LoginForm>) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Use HTTP Basic Auth: curl -u {}:<password> <url>",
        login_form.user_name
    ))
}
