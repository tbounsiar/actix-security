use actix_web::{App, dev, Error, FromRequest, get, HttpRequest, HttpResponse, HttpServer, Responder, Result, route};

use actix_security_core::http::security::middleware::SecurityTransform;
use actix_security_core::http::security::web::{WebAuthenticator, WebAuthorizer};
use actix_security_core::http::security::User;

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body(format!("Hello world! Logged In"))
}

#[get("/login")]
async fn login() -> impl Responder {
    HttpResponse::Ok().body(format!("Hello world! Login page"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("http://127.0.0.1:8080");
    HttpServer::new(move || {
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(authenticator)
                    .config_authorizer(authorizer)
            )
            .service(index)
            .service(login)
    })
        .bind("127.0.0.1:8080")?
        .run()
        .await
}

fn authenticator() -> WebAuthenticator {
    WebAuthenticator::new()
        .with_user(
            User::new(String::from("hi"), String::from("hi"))
        )
}

fn authorizer() -> WebAuthorizer {
    WebAuthorizer::new()
}
