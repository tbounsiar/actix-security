use actix_service::{Service, Transform};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::Error;
use futures::future::{ok, Ready};

use crate::http::auth::UserAuth;
use crate::http::middleware::SecurityService;
use crate::http::security::Authorize;

pub struct SecurityTransform<B, UA: UserAuth, Auth: Authorize<B>> {
    user_auth: Option<UA>,
    authorize: Option<Auth>,
}

impl<B, UA: UserAuth, Auth: Authorize<B>> SecurityTransform<B, UA, Auth> {
    pub fn new() -> Self {
        SecurityTransform { user_auth: None, authorize: None }
    }

    pub fn config_auth(&mut self, user_auth: UA) -> Self {
        self.user_auth = Some(user_auth);
        self;
    }

    pub fn config_authorize(&mut self, auth: Auth) -> Self {
        self.authorize = Some(auth);
        self;
    }
}

impl<UA: UserAuth, Auth: Authorize<B>, S, B> Transform<S> for SecurityTransform<B, UA, Auth>
    where
        S: Service<Request=ServiceRequest, Response=ServiceResponse<B>, Error=Error>,
        S::Future: 'static,
        B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = AuthService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthService::new(service))
    }
}