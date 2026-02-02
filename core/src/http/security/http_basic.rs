//! HTTP Basic Authentication support.
//!
//! # Spring Security Equivalent
//! `org.springframework.security.web.authentication.www.BasicAuthenticationFilter`
//!
//! # Feature Flag
//! Requires the `http-basic` feature (enabled by default).

#[cfg(feature = "http-basic")]
use actix_web::dev::ServiceRequest;
#[cfg(feature = "http-basic")]
use actix_web::http;
#[cfg(feature = "http-basic")]
use base64::prelude::*;

#[cfg(feature = "http-basic")]
use crate::http::security::user::User;

/// Extracts credentials from HTTP Basic Authentication header.
///
/// # Spring Security Equivalent
/// `BasicAuthenticationFilter`
///
/// Parses the `Authorization: Basic <base64(username:password)>` header.
#[cfg(feature = "http-basic")]
pub fn extract_basic_auth<F>(req: &ServiceRequest, verify: F) -> Option<User>
where
    F: FnOnce(&str, &str) -> Option<User>,
{
    let auth_header = req.headers().get(http::header::AUTHORIZATION)?;
    let auth_str = auth_header.to_str().ok()?;

    // Check for "Basic " prefix
    let credentials = auth_str.strip_prefix("Basic ")?;

    // Decode base64
    let decoded = BASE64_STANDARD.decode(credentials).ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;

    // Split username:password
    let (username, password) = decoded_str.split_once(':')?;

    verify(username, password)
}

/// HTTP Basic Authentication configuration.
///
/// # Spring Security Equivalent
/// `HttpSecurity.httpBasic()`
///
/// Provides configuration for HTTP Basic authentication including
/// custom realm names and entry points.
#[cfg(feature = "http-basic")]
#[derive(Clone)]
pub struct HttpBasicConfig {
    realm: String,
}

#[cfg(feature = "http-basic")]
impl HttpBasicConfig {
    /// Creates a new HTTP Basic configuration with default realm "Restricted".
    pub fn new() -> Self {
        HttpBasicConfig {
            realm: "Restricted".to_string(),
        }
    }

    /// Sets the realm name for the WWW-Authenticate header.
    ///
    /// # Example
    /// ```ignore
    /// let config = HttpBasicConfig::new().realm("MyApplication");
    /// ```
    pub fn realm(mut self, realm: &str) -> Self {
        self.realm = realm.to_string();
        self
    }

    /// Creates the WWW-Authenticate header value.
    pub fn www_authenticate_header(&self) -> String {
        format!("Basic realm=\"{}\"", self.realm)
    }
}

#[cfg(feature = "http-basic")]
impl Default for HttpBasicConfig {
    fn default() -> Self {
        Self::new()
    }
}
