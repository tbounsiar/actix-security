//! Extractors for accessing security context in handlers.
//!
//! # Spring Equivalent
//! `@AuthenticationPrincipal` annotation / `SecurityContextHolder`

use std::future::{ready, Ready};
use std::ops::Deref;

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpMessage, HttpRequest};

use crate::http::error::AuthError;
use crate::http::security::User;

/// Extractor for the authenticated user.
///
/// # Spring Equivalent
/// `@AuthenticationPrincipal User user` parameter or `SecurityContextHolder.getContext().getAuthentication().getPrincipal()`
///
/// # Usage
/// ```ignore
/// use actix_security_core::http::security::AuthenticatedUser;
///
/// async fn handler(user: AuthenticatedUser) -> impl Responder {
///     format!("Hello, {}!", user.get_username())
/// }
/// ```
///
/// # Errors
/// Returns `401 Unauthorized` if the user is not authenticated.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser(User);

impl AuthenticatedUser {
    /// Creates a new AuthenticatedUser wrapper.
    pub fn new(user: User) -> Self {
        AuthenticatedUser(user)
    }

    /// Returns the inner User.
    pub fn into_inner(self) -> User {
        self.0
    }
}

impl Deref for AuthenticatedUser {
    type Target = User;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRequest for AuthenticatedUser {
    type Error = AuthError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        match req.extensions().get::<User>().cloned() {
            Some(user) => ready(Ok(AuthenticatedUser(user))),
            None => ready(Err(AuthError::Unauthorized)),
        }
    }
}

/// Optional extractor for the authenticated user.
///
/// Returns `None` if not authenticated instead of an error.
///
/// # Usage
/// ```ignore
/// use actix_security_core::http::security::OptionalUser;
///
/// async fn handler(user: OptionalUser) -> impl Responder {
///     match user.into_inner() {
///         Some(u) => format!("Hello, {}!", u.get_username()),
///         None => "Hello, guest!".to_string(),
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct OptionalUser(Option<User>);

impl OptionalUser {
    /// Returns the inner Option<User>.
    pub fn into_inner(self) -> Option<User> {
        self.0
    }

    /// Returns true if a user is present.
    pub fn is_authenticated(&self) -> bool {
        self.0.is_some()
    }
}

impl Deref for OptionalUser {
    type Target = Option<User>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRequest for OptionalUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let user = req.extensions().get::<User>().cloned();
        ready(Ok(OptionalUser(user)))
    }
}

/// Extension trait for HttpRequest to check authentication.
pub trait SecurityExt {
    /// Returns a clone of the authenticated user if present.
    fn get_user(&self) -> Option<User>;

    /// Returns true if a user is authenticated.
    fn is_authenticated(&self) -> bool;

    /// Checks if the authenticated user has the specified role.
    fn has_role(&self, role: &str) -> bool;

    /// Checks if the authenticated user has any of the specified roles.
    fn has_any_role(&self, roles: &[&str]) -> bool;

    /// Checks if the authenticated user has the specified authority.
    fn has_authority(&self, authority: &str) -> bool;

    /// Checks if the authenticated user has any of the specified authorities.
    fn has_any_authority(&self, authorities: &[&str]) -> bool;
}

impl SecurityExt for HttpRequest {
    fn get_user(&self) -> Option<User> {
        self.extensions().get::<User>().cloned()
    }

    fn is_authenticated(&self) -> bool {
        self.extensions().get::<User>().is_some()
    }

    fn has_role(&self, role: &str) -> bool {
        self.extensions()
            .get::<User>()
            .is_some_and(|u| u.has_role(role))
    }

    fn has_any_role(&self, roles: &[&str]) -> bool {
        self.extensions()
            .get::<User>()
            .is_some_and(|u| u.has_any_role(roles))
    }

    fn has_authority(&self, authority: &str) -> bool {
        self.extensions()
            .get::<User>()
            .is_some_and(|u| u.has_authority(authority))
    }

    fn has_any_authority(&self, authorities: &[&str]) -> bool {
        self.extensions()
            .get::<User>()
            .is_some_and(|u| u.has_any_authority(authorities))
    }
}
