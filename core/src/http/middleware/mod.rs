use std::pin::Pin;

use actix_service::Service;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::Error;
use futures::Future;

pub use security_service::SecurityServiceFuture;
pub use security_transform::SecurityTransform;

mod http_security;
mod security_service;
mod security_transform;

pub type SecurityServiceFuture<B> = Pin<Box<dyn Future<Output=Result<ServiceResponse<B>, Error>>>>;