use std::collections::HashMap;
use std::pin::Pin;

use actix_service::Service;
use actix_web::{Error, http, HttpResponse};
use actix_web::body::Body;
use actix_web::dev::{ResourcePath, ServiceRequest, ServiceResponse};
use futures::future::{Either, ok, Ready};
use futures::Future;

use crate::http::security::config::{Authenticator, Authorizer};
use crate::http::security::middleware::{SecurityService, SecurityTransform};
use crate::http::security::user::User;

pub struct WebAuthenticator {
    users: HashMap<String, User>
}

impl WebAuthenticator {
    pub fn new() -> Self {
        WebAuthenticator {
            users: HashMap::new()
        }
    }

    pub fn with_user(mut self, user: User) -> WebAuthenticator {
        let user_name = user.get_username();
        match self.users.get(user_name) {
            Some(us) => {
                println!("User {} exists", user_name);
            }
            None => {
                self.users.insert(String::from(user_name), user);
            }
        }
        self
    }
}

impl Authenticator for WebAuthenticator {
    fn get_user(&self, req: &ServiceRequest) -> Option<&User> {
        let mut user: Option<&User> = None;
        match req.headers().get("user_name") {
            Some(hv) => {
                let user_name = hv.to_str().unwrap();
                match self.users.get(user_name) {
                    Some(u) => {
                        let password = req.headers().get("password").unwrap().to_str().unwrap();
                        if String::from(u.get_password()) == password {
                            user = Some(u);
                        }
                    }
                    None => {}
                }
            }
            None => {}
        };
        user
    }
}


pub struct WebAuthorizer {
    login_path: &'static str,
}

impl WebAuthorizer {
    pub fn new() -> Self {
        WebAuthorizer { login_path: "/login" }
    }
}

impl<
    Serv,
    Body
> Authorizer<Serv> for WebAuthorizer
    where
        Serv: Service<Request=ServiceRequest, Response=ServiceResponse<Body>, Error=Error>,
        Serv::Future: 'static,
        Body: 'static,
{
    type Response = ServiceResponse<Body>;
    type Error = Error;

    fn process(&self, service: &mut Serv, user: Option<&User>, req: ServiceRequest) -> Either<Serv::Future, Ready<Result<Self::Response, Self::Error>>> {
        let path = req.path();
        match user {
            Some(u) => {
                if path == self.login_path {
                    return Either::Right(ok(req.into_response(
                        HttpResponse::Found()
                            .header(http::header::LOCATION, "/")
                            .finish()
                            .into_body(),
                    )));
                }
                Either::Left(service.call(req))
            }
            None => {
                if path == self.login_path {
                    Either::Left(service.call(req))
                } else {
                    Either::Right(ok(req.into_response(
                        HttpResponse::Found()
                            .header(http::header::LOCATION, self.login_path)
                            .finish()
                            .into_body(),
                    )))
                }
            }
        }
    }
}

fn authenticator() -> WebAuthenticator {
    WebAuthenticator::new()
}

fn authorizer() -> WebAuthorizer {
    WebAuthorizer::new()
}

// pub fn web_security_transform<S>() -> SecurityTransform<
//     WebAuthenticator,
//     WebAuthorizer,
//     S
// >
//     where
//         S: Service<Request=ServiceRequest, Response=ServiceResponse<Body>, Error=Error>,
//         S::Future: 'static
// {
//     SecurityTransform::new()
//         .config_authenticator(authenticator)
//         .config_authorizer(authorizer)
// }