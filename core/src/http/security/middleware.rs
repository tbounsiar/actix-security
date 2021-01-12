use std::pin::Pin;
use std::task::{Context, Poll};

use actix_service::{Service, Transform};
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage};
use futures::Future;
use futures::future::{Either, ok, Ready};

use crate::http::security::config::{Authenticator, Authorizer};

pub struct SecurityTransform<Auth: Authenticator, Autho: Authorizer<Serv>, Serv: Service> {
    authenticator: Option<fn() -> Auth>,
    authorizer: Option<fn() -> Autho>,
    service: Option<Serv>,
}

impl<Auth: Authenticator, Autho: Authorizer<Serv>, Serv: Service> SecurityTransform<Auth, Autho, Serv> {
    pub fn new() -> Self {
        SecurityTransform {
            authorizer: None,
            authenticator: None,
            service: None,
        }
    }

    pub fn config_authenticator(mut self, authenticator: fn() -> Auth) -> SecurityTransform<Auth, Autho, Serv> {
        self.authenticator = Some(authenticator);
        self
    }

    pub fn config_authorizer(mut self, authorizer: fn() -> Autho) -> SecurityTransform<Auth, Autho, Serv> {
        self.authorizer = Some(authorizer);
        self
    }
}

impl<
    Auth: Authenticator,
    Autho,
    Serv,
    Body
> Transform<Serv> for SecurityTransform<Auth, Autho, Serv>
    where
        Serv: Service<Request=ServiceRequest, Response=ServiceResponse<Body>, Error=Error>,
        Serv::Future: 'static,
        Body: 'static,
        Autho: Authorizer<Serv, Response=ServiceResponse<Body>, Error=Error>,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<Body>;
    type Error = Error;
    type Transform = SecurityService<Auth, Autho, Serv>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: Serv) -> Self::Future {
        let authenticator = match &self.authenticator {
            Some(a) => Some(a()),
            None => None
        };
        let authorizer = match &self.authorizer {
            Some(a) => Some(a()),
            None => None
        };
        ok(
            SecurityService::new(
                authenticator,
                authorizer,
                service,
            )
        )
    }
}

pub struct SecurityService<Auth: Authenticator, Autho: Authorizer<Serv>, Serv: Service> {
    authenticator: Option<Auth>,
    authorizer: Option<Autho>,
    service: Serv,
}

impl<
    Auth: Authenticator,
    Autho: Authorizer<Serv>,
    Serv: Service
> SecurityService<Auth, Autho, Serv> {
    pub fn new(authenticator: Option<Auth>, authorizer: Option<Autho>, service: Serv) -> Self {
        SecurityService { authenticator, authorizer, service }
    }
}

impl<
    Auth: Authenticator,
    Autho,
    Serv,
    Body
> Service for SecurityService<Auth, Autho, Serv>
    where
        Serv: Service<Request=ServiceRequest, Response=ServiceResponse<Body>, Error=Error>,
        Serv::Future: 'static,
        Body: 'static,
        Autho: Authorizer<Serv, Response=ServiceResponse<Body>, Error=Error>,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<Body>;
    type Error = Error;
    type Future = Either<Serv::Future, Ready<Result<Self::Response, Self::Error>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let user = self.authenticator.as_ref().unwrap().get_user(&req);
        return self.authorizer.as_ref().unwrap().process(&mut self.service, user, req);
    }
}