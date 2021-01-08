use std::pin::Pin;
use std::task::{Context, Poll};

use actix_service::Service;
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage};
use futures::Future;

use crate::http::auth::UserAuth;
use crate::http::middleware::SecurityServiceFuture;
use crate::http::security::Authorize;

pub struct SecurityService<B, S, UA: UserAuth, Auth: Authorize<B>> {
    service: S,
    user_auth: Option<UA>,
    authorize: Option<Auth>,
}

impl<B, S, UA: UserAuth, Auth: Authorize<B>> SecurityService<B, S, UA, Auth> {
    pub fn new(service: S, user_auth: Option<UA>, authorize: Option<Auth>) -> Self <S> {
        SecurityService { service, user_auth, authorize }
    }
}

impl<S, B, UA: UserAuth, Auth: Authorize<B>> Service for SecurityService<B, S, UA, Auth>
    where
        S: Service<Request=ServiceRequest, Response=ServiceResponse<B>, Error=Error>,
        S::Future: 'static,
        B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = SecurityServiceFuture<B>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {

        println!("Hi from start. You requested: {}, method {}", req.path(), req.method());

        req.extensions_mut().insert(Auth::new(vec!["READ"]));

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;

            println!("Hi from response");
            Ok(res)
        })
    }
}