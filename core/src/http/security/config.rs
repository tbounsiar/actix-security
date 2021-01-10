use actix_service::Service;
use actix_web::body::Body;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::Error;
use futures::future::{Either, Ready};

use crate::http::security::user::User;

pub trait Authenticator {
    fn get_user(&self, req: &ServiceRequest) -> Option<&User>;
}

pub trait Authorizer<S: Service> {
    type Response;
    type Error;

    fn process(&self, service: &mut S, user: Option<&User>, req: ServiceRequest) -> Either<S::Future, Ready<Result<Self::Response, Self::Error>>>;
}

