//! Channel Security Module
//!
//! Provides channel security enforcement including HTTPS redirection
//! and port mapping. Similar to Spring Security's channel security.
//!
//! # Features
//!
//! - **HTTPS Enforcement**: Redirect HTTP requests to HTTPS
//! - **Port Mapping**: Configure custom HTTP/HTTPS port mappings
//! - **Path-based Rules**: Apply different security to different paths
//! - **Flexible Configuration**: Customize redirect behavior
//!
//! # Example
//!
//! ```rust,ignore
//! use actix_security::http::security::channel::{ChannelSecurity, ChannelSecurityConfig};
//! use actix_web::{App, HttpServer};
//!
//! let channel_security = ChannelSecurity::new(
//!     ChannelSecurityConfig::new()
//!         .require_https(&["/login", "/api/**"])
//!         .allow_http(&["/health", "/public/**"])
//! );
//!
//! HttpServer::new(move || {
//!     App::new()
//!         .wrap(channel_security.clone())
//!         // ... routes
//! })
//! .bind("0.0.0.0:80")?
//! .bind_rustls("0.0.0.0:443", config)?
//! .run()
//! .await
//! ```
//!
//! # Spring Equivalent
//!
//! ```java
//! http.requiresChannel()
//!     .requestMatchers("/login", "/api/**").requiresSecure()
//!     .requestMatchers("/public/**").requiresInsecure();
//! ```

use std::future::{ready, Ready};
use std::sync::Arc;

use actix_service::{Service, Transform};
use actix_web::{
    body::EitherBody,
    dev::{ServiceRequest, ServiceResponse},
    http::{header, StatusCode},
    Error, HttpResponse,
};
use futures_util::future::LocalBoxFuture;

use super::ant_matcher::AntMatcher;

/// Channel security requirement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChannelRequirement {
    /// Require HTTPS
    Secure,
    /// Require HTTP (insecure)
    Insecure,
    /// Allow any channel
    #[default]
    Any,
}

/// Port mapping for HTTP/HTTPS redirects
#[derive(Debug, Clone)]
pub struct PortMapper {
    http_port: u16,
    https_port: u16,
}

impl Default for PortMapper {
    fn default() -> Self {
        Self {
            http_port: 80,
            https_port: 443,
        }
    }
}

impl PortMapper {
    /// Create a new port mapper with custom ports
    pub fn new(http_port: u16, https_port: u16) -> Self {
        Self {
            http_port,
            https_port,
        }
    }

    /// Get the HTTPS port for redirect
    pub fn get_https_port(&self) -> u16 {
        self.https_port
    }

    /// Get the HTTP port for redirect
    pub fn get_http_port(&self) -> u16 {
        self.http_port
    }
}

/// Rule for channel security
#[derive(Debug, Clone)]
struct ChannelRule {
    matcher: AntMatcher,
    requirement: ChannelRequirement,
}

/// Configuration for channel security
#[derive(Debug, Clone)]
pub struct ChannelSecurityConfig {
    rules: Vec<ChannelRule>,
    port_mapper: PortMapper,
    default_requirement: ChannelRequirement,
    redirect_status: StatusCode,
    preserve_host: bool,
}

impl Default for ChannelSecurityConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelSecurityConfig {
    /// Create a new configuration
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            port_mapper: PortMapper::default(),
            default_requirement: ChannelRequirement::Any,
            redirect_status: StatusCode::MOVED_PERMANENTLY,
            preserve_host: true,
        }
    }

    /// Require HTTPS for all paths (strict mode)
    pub fn require_https_everywhere() -> Self {
        Self::new().default_requirement(ChannelRequirement::Secure)
    }

    /// Add paths that require HTTPS
    pub fn require_https(mut self, patterns: &[&str]) -> Self {
        for pattern in patterns {
            self.rules.push(ChannelRule {
                matcher: AntMatcher::new(pattern),
                requirement: ChannelRequirement::Secure,
            });
        }
        self
    }

    /// Add paths that allow HTTP
    pub fn allow_http(mut self, patterns: &[&str]) -> Self {
        for pattern in patterns {
            self.rules.push(ChannelRule {
                matcher: AntMatcher::new(pattern),
                requirement: ChannelRequirement::Insecure,
            });
        }
        self
    }

    /// Add paths that allow any channel
    pub fn allow_any(mut self, patterns: &[&str]) -> Self {
        for pattern in patterns {
            self.rules.push(ChannelRule {
                matcher: AntMatcher::new(pattern),
                requirement: ChannelRequirement::Any,
            });
        }
        self
    }

    /// Set the default requirement for paths not matching any rule
    pub fn default_requirement(mut self, requirement: ChannelRequirement) -> Self {
        self.default_requirement = requirement;
        self
    }

    /// Set custom port mapping
    pub fn port_mapper(mut self, http_port: u16, https_port: u16) -> Self {
        self.port_mapper = PortMapper::new(http_port, https_port);
        self
    }

    /// Set the HTTP redirect status code (default: 301 Moved Permanently)
    ///
    /// Common values:
    /// - 301: Moved Permanently (cached by browsers)
    /// - 302: Found (temporary redirect)
    /// - 307: Temporary Redirect (preserves method)
    /// - 308: Permanent Redirect (preserves method, cached)
    pub fn redirect_status(mut self, status: StatusCode) -> Self {
        self.redirect_status = status;
        self
    }

    /// Use temporary redirect (302 Found)
    pub fn temporary_redirect(self) -> Self {
        self.redirect_status(StatusCode::FOUND)
    }

    /// Use permanent redirect that preserves HTTP method (308)
    pub fn permanent_redirect_preserve_method(self) -> Self {
        self.redirect_status(StatusCode::PERMANENT_REDIRECT)
    }

    /// Set whether to preserve the Host header in redirects
    pub fn preserve_host(mut self, preserve: bool) -> Self {
        self.preserve_host = preserve;
        self
    }

    /// Get the requirement for a given path
    fn get_requirement(&self, path: &str) -> ChannelRequirement {
        for rule in &self.rules {
            if rule.matcher.matches(path) {
                return rule.requirement;
            }
        }
        self.default_requirement
    }
}

/// Channel security middleware
#[derive(Clone)]
pub struct ChannelSecurity {
    config: Arc<ChannelSecurityConfig>,
}

impl ChannelSecurity {
    /// Create a new channel security middleware
    pub fn new(config: ChannelSecurityConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Create with HTTPS required everywhere
    pub fn https_everywhere() -> Self {
        Self::new(ChannelSecurityConfig::require_https_everywhere())
    }

    /// Get the configuration
    pub fn config(&self) -> &ChannelSecurityConfig {
        &self.config
    }
}

impl<S, B> Transform<S, ServiceRequest> for ChannelSecurity
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = ChannelSecurityService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(ChannelSecurityService {
            service,
            config: Arc::clone(&self.config),
        }))
    }
}

/// Channel security service
pub struct ChannelSecurityService<S> {
    service: S,
    config: Arc<ChannelSecurityConfig>,
}

impl<S, B> Service<ServiceRequest> for ChannelSecurityService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let path = req.path().to_string();
        let requirement = self.config.get_requirement(&path);

        // Determine if request is secure
        let is_secure = req.connection_info().scheme() == "https";

        // Check if redirect is needed
        let redirect_url = match requirement {
            ChannelRequirement::Secure if !is_secure => {
                Some(self.build_redirect_url(&req, true))
            }
            ChannelRequirement::Insecure if is_secure => {
                Some(self.build_redirect_url(&req, false))
            }
            _ => None,
        };

        if let Some(url) = redirect_url {
            let response = HttpResponse::build(self.config.redirect_status)
                .insert_header((header::LOCATION, url))
                .finish()
                .map_into_right_body();

            let (http_req, _) = req.into_parts();
            return Box::pin(async move { Ok(ServiceResponse::new(http_req, response)) });
        }

        // No redirect needed, proceed with request
        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res.map_into_left_body())
        })
    }
}

impl<S> ChannelSecurityService<S> {
    /// Build the redirect URL
    fn build_redirect_url(&self, req: &ServiceRequest, to_https: bool) -> String {
        let conn_info = req.connection_info();
        let scheme = if to_https { "https" } else { "http" };

        // Get host
        let host = if self.config.preserve_host {
            conn_info.host().to_string()
        } else {
            // Strip port from host if present
            conn_info
                .host()
                .split(':')
                .next()
                .unwrap_or("localhost")
                .to_string()
        };

        // Get appropriate port
        let port = if to_https {
            self.config.port_mapper.get_https_port()
        } else {
            self.config.port_mapper.get_http_port()
        };

        // Build URL
        let path_and_query = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        // Strip existing port from host
        let host_without_port = host.split(':').next().unwrap_or(&host);

        // Only include port if non-standard
        let port_str = if (to_https && port == 443) || (!to_https && port == 80) {
            String::new()
        } else {
            format!(":{}", port)
        };

        format!("{}://{}{}{}", scheme, host_without_port, port_str, path_and_query)
    }
}

/// Helper trait for building channel security rules
pub trait ChannelSecurityExt {
    /// Require HTTPS for this path pattern
    fn requires_secure(self) -> Self;

    /// Allow HTTP for this path pattern
    fn requires_insecure(self) -> Self;
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_requirement() {
        assert_eq!(ChannelRequirement::default(), ChannelRequirement::Any);
    }

    #[test]
    fn test_port_mapper_default() {
        let mapper = PortMapper::default();
        assert_eq!(mapper.get_http_port(), 80);
        assert_eq!(mapper.get_https_port(), 443);
    }

    #[test]
    fn test_port_mapper_custom() {
        let mapper = PortMapper::new(8080, 8443);
        assert_eq!(mapper.get_http_port(), 8080);
        assert_eq!(mapper.get_https_port(), 8443);
    }

    #[test]
    fn test_config_default() {
        let config = ChannelSecurityConfig::new();
        assert_eq!(config.default_requirement, ChannelRequirement::Any);
        assert_eq!(config.redirect_status, StatusCode::MOVED_PERMANENTLY);
    }

    #[test]
    fn test_config_require_https() {
        let config = ChannelSecurityConfig::new()
            .require_https(&["/login", "/api/**"]);

        assert_eq!(
            config.get_requirement("/login"),
            ChannelRequirement::Secure
        );
        assert_eq!(
            config.get_requirement("/api/users"),
            ChannelRequirement::Secure
        );
        assert_eq!(
            config.get_requirement("/public"),
            ChannelRequirement::Any
        );
    }

    #[test]
    fn test_config_allow_http() {
        let config = ChannelSecurityConfig::new()
            .default_requirement(ChannelRequirement::Secure)
            .allow_http(&["/health", "/public/**"]);

        assert_eq!(
            config.get_requirement("/health"),
            ChannelRequirement::Insecure
        );
        assert_eq!(
            config.get_requirement("/public/images/logo.png"),
            ChannelRequirement::Insecure
        );
        assert_eq!(
            config.get_requirement("/api/users"),
            ChannelRequirement::Secure
        );
    }

    #[test]
    fn test_config_https_everywhere() {
        let config = ChannelSecurityConfig::require_https_everywhere();
        assert_eq!(config.default_requirement, ChannelRequirement::Secure);
    }

    #[test]
    fn test_config_redirect_status() {
        let config = ChannelSecurityConfig::new()
            .temporary_redirect();
        assert_eq!(config.redirect_status, StatusCode::FOUND);

        let config = ChannelSecurityConfig::new()
            .permanent_redirect_preserve_method();
        assert_eq!(config.redirect_status, StatusCode::PERMANENT_REDIRECT);
    }

    #[test]
    fn test_config_port_mapper() {
        let config = ChannelSecurityConfig::new()
            .port_mapper(8080, 8443);

        assert_eq!(config.port_mapper.get_http_port(), 8080);
        assert_eq!(config.port_mapper.get_https_port(), 8443);
    }

    #[test]
    fn test_channel_security_creation() {
        let cs = ChannelSecurity::https_everywhere();
        assert_eq!(
            cs.config().default_requirement,
            ChannelRequirement::Secure
        );
    }

    #[test]
    fn test_mixed_rules() {
        let config = ChannelSecurityConfig::new()
            .require_https(&["/admin/**", "/login"])
            .allow_any(&["/public/**"])
            .allow_http(&["/health"]);

        assert_eq!(
            config.get_requirement("/admin/dashboard"),
            ChannelRequirement::Secure
        );
        assert_eq!(
            config.get_requirement("/login"),
            ChannelRequirement::Secure
        );
        assert_eq!(
            config.get_requirement("/public/css/style.css"),
            ChannelRequirement::Any
        );
        assert_eq!(
            config.get_requirement("/health"),
            ChannelRequirement::Insecure
        );
    }
}
