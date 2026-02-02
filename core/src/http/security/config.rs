//! Configuration traits for authentication and authorization.
//!
//! # Spring Equivalent
//! `AuthenticationProvider` and `AccessDecisionManager` interfaces

use actix_web::body::EitherBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::Error;
use futures_util::future::LocalBoxFuture;

use crate::http::security::user::User;

/// Trait for extracting user identity from an HTTP request.
///
/// # Spring Equivalent
/// `AuthenticationProvider` / `UserDetailsService`
///
/// # Implementation Note
/// Returns an owned `User` so it can be stored in request extensions
/// for access by handlers.
pub trait Authenticator {
    /// Attempts to authenticate the request and returns the user if successful.
    fn get_user(&self, req: &ServiceRequest) -> Option<User>;
}

/// Trait for deciding whether an authenticated user can access a resource.
///
/// # Spring Equivalent
/// `AccessDecisionManager` / `AuthorizationManager`
///
/// The `process` method returns a boxed future that resolves to:
/// - `EitherBody::left()` when forwarding to the inner service
/// - `EitherBody::right()` for custom responses (redirects, forbidden, etc.)
pub trait Authorizer<B> {
    /// Processes the authorization decision.
    ///
    /// # Arguments
    /// * `req` - The incoming request
    /// * `user` - The authenticated user (if any)
    /// * `next` - Closure to call the next service in the chain
    fn process(
        &self,
        req: ServiceRequest,
        user: Option<&User>,
        next: impl FnOnce(ServiceRequest) -> LocalBoxFuture<'static, Result<ServiceResponse<B>, Error>>
            + 'static,
    ) -> LocalBoxFuture<'static, Result<ServiceResponse<EitherBody<B>>, Error>>;
}
