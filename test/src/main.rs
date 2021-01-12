// 1.4.0
use std::sync::Mutex;

use actix_web::{App, dev, Error, FromRequest, get, HttpRequest, HttpResponse, HttpServer, post, Responder, Result, route, Scope, web};
use actix_web::body::Body;
use actix_web::cookie::Cookie;
use actix_web::dev::{HttpServiceFactory, ServiceRequest, ServiceResponse};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

use actix_security_core::http::security::{AuthenticationManager, User};
use actix_security_core::http::security::manager::AuthorizationManager;
use actix_security_core::http::security::middleware::SecurityTransform;
use actix_security_core::http::security::web::{Access, MemoryAuthenticator, RequestMatcherAuthorizer};
use std::ops::Deref;

lazy_static! {
    static ref MEMORY_AUTHENTICATOR: Mutex<MemoryAuthenticator> = Mutex::new(
        AuthenticationManager::in_memory_authentication()
            .with_user(
                User::new(String::from("hi"), String::from("hi"))
                    .roles(&[String::from("ADMIN")])
            )
            .with_user(
                User::new(String::from("his"), String::from("his"))
                    .roles(&[String::from("USER")])
            )
       );
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body(format!("Hello world! Logged In"))
}

#[get("/login")]
async fn login() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../web/login.html"))
}

#[derive(Serialize, Deserialize)]
struct LoginForm {
    user_name: String,
    password: String,
}

#[post("/login")]
async fn post_login(login_form: web::Form<LoginForm>) -> impl Responder {
    let id = MEMORY_AUTHENTICATOR.lock().unwrap().login(login_form.0.user_name, login_form.0.password);
    match id {
        Some(i) => {
            HttpResponse::Ok()
                .header("Set-Cookie", format!("user_id={}", i))
                .body("Login success")
        }
        None => {
            HttpResponse::Ok()
                .body("Login error")
        }
    }
}

#[get("/admin/hello")]
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

    HttpServer::new(move ||  {
        App::new()
            .service(
                web::scope("/")
                    .wrap(
                        SecurityTransform::new()
                            .config_authenticator(|| MEMORY_AUTHENTICATOR.into_inner().unwrap()
                                                  //     .with_user(
                                                  //     User::new(String::from("hi"), String::from("hi"))
                                                  //         .roles(&[String::from("ADMIN")])
                                                  // )
                                                  //     .with_user(
                                                  //         User::new(String::from("his"), String::from("his"))
                                                  //             .roles(&[String::from("USER")])
                                                  //     )
                            )
                            .config_authorizer(authorizer)
                    )
                    .service(index)
                    .service(login)
                    .service(user)
                    .service(admin)
                    .service(post_login)
            )
    })
        .bind("127.0.0.1:8080")?
        .run()
        .await
}

fn authorizer() -> RequestMatcherAuthorizer {
    AuthorizationManager::request_matcher()
        .add_matcher("/admin/**", Access::new().roles(vec!["ADMIN"]))
        .add_matcher("/user/**", Access::new().roles(vec!["ADMIN", "USER"]))
}