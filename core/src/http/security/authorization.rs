use std::collections::HashMap;

use actix_service::Service;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::Error;

use crate::http::auth::{Access, AccessFn};
use crate::http::middleware::SecurityServiceFuture;
use crate::http::security::authorize_requests::AuthorizeRequests;

pub struct Authorization {
    pub url: Option<&'static str>,
    pub access: Access,
}

pub trait Authorize<B> {
    fn is_authorized(self, authorization: &Authorization) -> bool;
    fn process(
        self,
        service: Service<Request=ServiceRequest, Response=ServiceResponse<B>, Error=Error>,
        service_request: ServiceRequest,
    ) -> SecurityServiceFuture<B>;
}