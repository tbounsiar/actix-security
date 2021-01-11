use actix_web::{App, dev, Error, FromRequest, get, HttpRequest, HttpResponse, HttpServer, Responder, Result, route};

use actix_security_core::http::security::{AuthenticationManager, User};
use actix_security_core::http::security::manager::AuthorizationManager;
use actix_security_core::http::security::middleware::SecurityTransform;
use actix_security_core::http::security::web::{Access, MemoryAuthenticator, RequestMatcherAuthorizer};

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body(format!("Hello world! Logged In"))
}

#[get("/login")]
async fn login() -> impl Responder {
    HttpResponse::Ok().body(format!("Hello world! Login page"))
}

#[get("/admin/")]
async fn admin() -> impl Responder {
    HttpResponse::Ok().body(format!("Hello world! Admin page"))
}

#[get("/user/")]
async fn user() -> impl Responder {
    HttpResponse::Ok().body(format!("Hello world! User page"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("http://127.0.0.1:8080");
    HttpServer::new(move || {
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(|| AuthenticationManager::in_memory_authentication()
                        .with_user(
                            User::new(String::from("hi"), String::from("hi"))
                                .roles(&[String::from("ADMIN")])
                        )
                        .with_user(
                            User::new(String::from("his"), String::from("his"))
                                .roles(&[String::from("USER")])
                        ))
                    .config_authorizer(authorizer)
            )
            .service(index)
            .service(login)
    })
        .bind("127.0.0.1:8080")?
        .run()
        .await
}

fn authorizer() -> RequestMatcherAuthorizer {
    AuthorizationManager::request_matcher()
        .add_matcher("/admin/**", Access::new().roles(vec!["ADMIN"]))
        .add_matcher("/web/**", Access::new().roles(vec!["ADMIN", "USER"]));
}
