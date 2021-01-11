use std::collections::HashMap;
use std::pin::Pin;

use actix_service::Service;
use actix_web::{Error, http, HttpResponse};
use actix_web::body::Body;
use actix_web::dev::{ResourcePath, ServiceRequest, ServiceResponse};
use futures::future::{Either, ok, Ready};
use futures::Future;
use regex::Regex;

use crate::http::security::config::{Authenticator, Authorizer};
use crate::http::security::middleware::{SecurityService, SecurityTransform};
use crate::http::security::user::User;

pub struct MemoryAuthenticator {
    users: HashMap<String, User>
}

impl MemoryAuthenticator {
    pub fn new() -> Self {
        MemoryAuthenticator {
            users: HashMap::new()
        }
    }

    pub fn with_user(mut self, user: User) -> MemoryAuthenticator {
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

impl Authenticator for MemoryAuthenticator {
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

pub struct RequestMatcherAuthorizer {
    login_url: &'static str,
    matchers: HashMap<String, Access>,
}

impl RequestMatcherAuthorizer {
    pub fn new() -> Self {
        RequestMatcherAuthorizer { login_url: "/login", matchers: HashMap::new() }
    }

    pub fn add_matcher(mut self, url_regex: &'static str, access: Access) -> Self {
        self.matchers.insert(String::from(url_regex), access);
        self
    }

    pub fn login_url(mut self, url: &'static str) -> Self {
        self.login_url == url;
        self
    }

    pub fn matchs(&self, path: &str) -> Option<&Access> {
        for matcher in &self.matchers {
            let re = Regex::new(matcher.0.as_str()).unwrap();
            if re.is_match(path) {
                return Some(matcher.1);
            }
        }
        None
    }
}

impl<
    Serv,
    Body
> Authorizer<Serv> for RequestMatcherAuthorizer
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
                if path == self.login_url {
                    return Either::Right(ok(req.into_response(
                        HttpResponse::Found()
                            .header(http::header::LOCATION, "/")
                            .finish()
                            .into_body(),
                    )));
                }
                match self.matchs(path) {
                    Some(access) => {
                        if u.has_authority(access.authorities) || u.has_roles(access.roles) {
                            return Either::Left(service.call(req));
                        }
                    }
                    None => {}
                }
                Either::Right(ok(
                    req.into_response(
                        HttpResponse::Forbidden()
                            .finish()
                            .into_body()
                    )))
            }
            None => {
                if path == self.login_url {
                    Either::Left(service.call(req))
                } else {
                    Either::Right(ok(req.into_response(
                        HttpResponse::Found()
                            .header(http::header::LOCATION, self.login_url)
                            .finish()
                            .into_body(),
                    )))
                }
            }
        }
    }
}

pub struct Access {
    roles: Vec<String>,
    authorities: Vec<String>,
}

impl Access {
    pub fn new() -> Self {
        Access {
            roles: Vec::new(),
            authorities: Vec::new(),
        }
    }

    pub fn roles(mut self, roles: Vec<&str>) -> Access {
        for role in roles {
            if self.roles.contains(&String::from(role)) {
                continue;
            }
            self.roles.push(String::from(role));
        }
        self
    }

    pub fn authorities(mut self, authorities: Vec<&str>) -> Access {
        for authority in authorities {
            if self.authorities.contains(&String::from(authority)) {
                continue;
            }
            self.authorities.push(String::from(authority));
        }
        self
    }
}