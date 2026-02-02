//! Security middleware for Actix Web.
//!
//! # Spring Equivalent
//! `SecurityFilterChain` / `FilterChainProxy`

use std::rc::Rc;

use actix_service::{Service, Transform};
use actix_web::body::EitherBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::{Error, HttpMessage};
use futures_util::future::{ok, LocalBoxFuture, Ready};

use crate::http::security::config::{Authenticator, Authorizer};

/// Security middleware factory.
///
/// # Spring Equivalent
/// `SecurityFilterChain`
///
/// # Example
/// ```ignore
/// App::new().wrap(
///     SecurityTransform::new()
///         .config_authenticator(my_authenticator)
///         .config_authorizer(my_authorizer)
/// )
/// ```
pub struct SecurityTransform<Auth, Autho> {
    authenticator: Option<fn() -> Auth>,
    authorizer: Option<fn() -> Autho>,
}

impl<Auth, Autho> SecurityTransform<Auth, Autho> {
    pub fn new() -> Self {
        SecurityTransform {
            authorizer: None,
            authenticator: None,
        }
    }

    pub fn config_authenticator(mut self, authenticator: fn() -> Auth) -> Self {
        self.authenticator = Some(authenticator);
        self
    }

    pub fn config_authorizer(mut self, authorizer: fn() -> Autho) -> Self {
        self.authorizer = Some(authorizer);
        self
    }
}

impl<Auth, Autho> Default for SecurityTransform<Auth, Autho> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, B, Auth, Autho> Transform<S, ServiceRequest> for SecurityTransform<Auth, Autho>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    Auth: Authenticator + 'static,
    Autho: Authorizer<B> + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = SecurityService<Auth, Autho, S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        let authenticator = self.authenticator.map(|f| f());
        let authorizer = self.authorizer.map(|f| f());

        ok(SecurityService {
            authenticator,
            authorizer,
            service: Rc::new(service),
        })
    }
}

/// Security middleware service.
///
/// # Spring Equivalent
/// `FilterChainProxy`
pub struct SecurityService<Auth, Autho, S> {
    authenticator: Option<Auth>,
    authorizer: Option<Autho>,
    service: Rc<S>,
}

impl<Auth, Autho, S, B> Service<ServiceRequest> for SecurityService<Auth, Autho, S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    Auth: Authenticator,
    Autho: Authorizer<B>,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);

        // Step 1: Authenticate - extract user from request
        let user = self
            .authenticator
            .as_ref()
            .and_then(|auth| auth.get_user(&req));

        // Step 2: Store user in request extensions (if authenticated)
        // This makes the user available to handlers via AuthenticatedUser extractor
        if let Some(ref u) = user {
            req.extensions_mut().insert(u.clone());
        }

        // Step 3: Process authorization
        if let Some(authorizer) = &self.authorizer {
            // Create a closure to call the next service
            let next = move |req: ServiceRequest| -> LocalBoxFuture<'static, Result<ServiceResponse<B>, Error>> {
                let fut = service.call(req);
                Box::pin(fut)
            };

            authorizer.process(req, user.as_ref(), next)
        } else {
            // No authorizer configured, pass through with EitherBody::left
            let fut = service.call(req);
            Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            })
        }
    }
}
