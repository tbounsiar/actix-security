//! WebSocket security configuration.
//!
//! Provides a unified configuration for WebSocket security including
//! authentication requirements and origin validation.

use actix_web::{HttpMessage, HttpRequest};

use crate::http::security::User;

use super::error::WebSocketSecurityError;
use super::extractor::WebSocketUpgrade;
use super::origin::OriginValidator;

/// Configuration for WebSocket security.
///
/// This provides a unified way to configure security for WebSocket endpoints,
/// combining authentication requirements and origin validation.
///
/// # Spring Security Equivalent
/// `WebSocketSecurityConfigurer` / `AbstractSecurityWebSocketMessageBrokerConfigurer`
///
/// # Example
///
/// ```ignore
/// use actix_security::http::security::websocket::WebSocketSecurityConfig;
///
/// // Create configuration
/// let ws_config = WebSocketSecurityConfig::new()
///     .allowed_origins(vec!["https://myapp.com".into()])
///     .require_authentication(true)
///     .required_roles(vec!["USER".into()]);
///
/// // Use in handler
/// #[get("/ws")]
/// async fn ws_handler(
///     req: HttpRequest,
///     stream: web::Payload,
///     config: web::Data<WebSocketSecurityConfig>,
/// ) -> Result<HttpResponse, actix_web::Error> {
///     let upgrade = config.validate_upgrade(&req)?;
///     // ... upgrade to WebSocket
/// }
/// ```
#[derive(Debug, Clone)]
pub struct WebSocketSecurityConfig {
    /// Origin validator
    origin_validator: OriginValidator,
    /// Require authentication for WebSocket connections
    require_authentication: bool,
    /// Required roles (any of these)
    required_roles: Vec<String>,
    /// Required authorities (any of these)
    required_authorities: Vec<String>,
}

impl Default for WebSocketSecurityConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl WebSocketSecurityConfig {
    /// Creates a new WebSocket security configuration with default settings.
    ///
    /// Default settings:
    /// - No origin validation (allow any)
    /// - Authentication not required
    /// - No role/authority requirements
    pub fn new() -> Self {
        Self {
            origin_validator: OriginValidator::allow_any(),
            require_authentication: false,
            required_roles: Vec::new(),
            required_authorities: Vec::new(),
        }
    }

    /// Sets the allowed origins for WebSocket connections.
    ///
    /// # Arguments
    /// * `origins` - List of allowed origin URLs
    ///
    /// # Example
    /// ```ignore
    /// let config = WebSocketSecurityConfig::new()
    ///     .allowed_origins(vec!["https://myapp.com".into()]);
    /// ```
    pub fn allowed_origins(mut self, origins: Vec<String>) -> Self {
        let origins_refs: Vec<&str> = origins.iter().map(|s| s.as_str()).collect();
        self.origin_validator = OriginValidator::new(&origins_refs);
        self
    }

    /// Sets a custom origin validator.
    ///
    /// # Example
    /// ```ignore
    /// let validator = OriginValidator::builder()
    ///     .allow("https://myapp.com")
    ///     .allow_localhost_in_dev(true)
    ///     .build();
    ///
    /// let config = WebSocketSecurityConfig::new()
    ///     .origin_validator(validator);
    /// ```
    pub fn origin_validator(mut self, validator: OriginValidator) -> Self {
        self.origin_validator = validator;
        self
    }

    /// Requires authentication for WebSocket connections.
    ///
    /// When enabled, unauthenticated WebSocket upgrade requests will be rejected.
    ///
    /// # Example
    /// ```ignore
    /// let config = WebSocketSecurityConfig::new()
    ///     .require_authentication(true);
    /// ```
    pub fn require_authentication(mut self, require: bool) -> Self {
        self.require_authentication = require;
        self
    }

    /// Sets required roles for WebSocket connections.
    ///
    /// Users must have at least one of the specified roles.
    /// Automatically enables authentication requirement.
    ///
    /// # Example
    /// ```ignore
    /// let config = WebSocketSecurityConfig::new()
    ///     .required_roles(vec!["USER".into(), "ADMIN".into()]);
    /// ```
    pub fn required_roles(mut self, roles: Vec<String>) -> Self {
        self.required_roles = roles;
        if !self.required_roles.is_empty() {
            self.require_authentication = true;
        }
        self
    }

    /// Sets required authorities for WebSocket connections.
    ///
    /// Users must have at least one of the specified authorities.
    /// Automatically enables authentication requirement.
    ///
    /// # Example
    /// ```ignore
    /// let config = WebSocketSecurityConfig::new()
    ///     .required_authorities(vec!["ws:connect".into()]);
    /// ```
    pub fn required_authorities(mut self, authorities: Vec<String>) -> Self {
        self.required_authorities = authorities;
        if !self.required_authorities.is_empty() {
            self.require_authentication = true;
        }
        self
    }

    /// Validates a WebSocket upgrade request.
    ///
    /// This method performs all configured security checks:
    /// 1. Origin validation (CSWSH prevention)
    /// 2. Authentication check (if required)
    /// 3. Role check (if configured)
    /// 4. Authority check (if configured)
    ///
    /// # Returns
    /// - `Ok(WebSocketUpgrade)` - Validation passed, safe to upgrade
    /// - `Err(WebSocketSecurityError)` - Validation failed
    ///
    /// # Example
    /// ```ignore
    /// let config = WebSocketSecurityConfig::new()
    ///     .allowed_origins(vec!["https://myapp.com".into()])
    ///     .require_authentication(true);
    ///
    /// #[get("/ws")]
    /// async fn ws_handler(req: HttpRequest, stream: web::Payload) -> Result<HttpResponse, Error> {
    ///     let upgrade = config.validate_upgrade(&req)?;
    ///     let user = upgrade.into_user().unwrap();
    ///     // ... upgrade to WebSocket
    /// }
    /// ```
    pub fn validate_upgrade(
        &self,
        req: &HttpRequest,
    ) -> Result<WebSocketUpgrade, WebSocketSecurityError> {
        // 1. Validate origin
        self.origin_validator.validate(req)?;

        // 2. Get user from request extensions
        let user = req.extensions().get::<User>().cloned();

        // 3. Check authentication requirement
        if self.require_authentication && user.is_none() {
            return Err(WebSocketSecurityError::Unauthorized);
        }

        // 4. Check role requirement
        if !self.required_roles.is_empty() {
            let roles_refs: Vec<&str> = self.required_roles.iter().map(|s| s.as_str()).collect();
            if !user.as_ref().is_some_and(|u| u.has_any_role(&roles_refs)) {
                return Err(WebSocketSecurityError::MissingRole {
                    role: self.required_roles.join(", "),
                });
            }
        }

        // 5. Check authority requirement
        if !self.required_authorities.is_empty() {
            let auth_refs: Vec<&str> = self
                .required_authorities
                .iter()
                .map(|s| s.as_str())
                .collect();
            if !user
                .as_ref()
                .is_some_and(|u| u.has_any_authority(&auth_refs))
            {
                return Err(WebSocketSecurityError::MissingAuthority {
                    authority: self.required_authorities.join(", "),
                });
            }
        }

        // 6. Extract origin for logging/debugging
        let origin = req
            .headers()
            .get("origin")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        Ok(WebSocketUpgrade::new(user, origin))
    }
}

/// Builder for more complex WebSocket security configurations.
#[derive(Debug, Clone, Default)]
pub struct WebSocketSecurityConfigBuilder {
    config: WebSocketSecurityConfig,
}

impl WebSocketSecurityConfigBuilder {
    /// Creates a new builder.
    pub fn new() -> Self {
        Self {
            config: WebSocketSecurityConfig::new(),
        }
    }

    /// Sets allowed origins.
    pub fn allowed_origins(mut self, origins: Vec<String>) -> Self {
        self.config = self.config.allowed_origins(origins);
        self
    }

    /// Sets a custom origin validator.
    pub fn origin_validator(mut self, validator: OriginValidator) -> Self {
        self.config = self.config.origin_validator(validator);
        self
    }

    /// Requires authentication.
    pub fn require_authentication(mut self) -> Self {
        self.config = self.config.require_authentication(true);
        self
    }

    /// Sets required roles.
    pub fn required_roles(mut self, roles: Vec<String>) -> Self {
        self.config = self.config.required_roles(roles);
        self
    }

    /// Sets required authorities.
    pub fn required_authorities(mut self, authorities: Vec<String>) -> Self {
        self.config = self.config.required_authorities(authorities);
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> WebSocketSecurityConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    fn create_request_with_user(user: User) -> HttpRequest {
        let req = TestRequest::default()
            .insert_header(("origin", "https://myapp.com"))
            .to_http_request();
        req.extensions_mut().insert(user);
        req
    }

    #[test]
    fn test_default_config_allows_all() {
        let config = WebSocketSecurityConfig::new();
        let req = TestRequest::default()
            .insert_header(("origin", "https://any-origin.com"))
            .to_http_request();

        assert!(config.validate_upgrade(&req).is_ok());
    }

    #[test]
    fn test_origin_validation() {
        let config =
            WebSocketSecurityConfig::new().allowed_origins(vec!["https://myapp.com".into()]);

        // Valid origin
        let req = TestRequest::default()
            .insert_header(("origin", "https://myapp.com"))
            .to_http_request();
        assert!(config.validate_upgrade(&req).is_ok());

        // Invalid origin
        let req = TestRequest::default()
            .insert_header(("origin", "https://evil.com"))
            .to_http_request();
        assert!(config.validate_upgrade(&req).is_err());
    }

    #[test]
    fn test_authentication_requirement() {
        let config = WebSocketSecurityConfig::new()
            .origin_validator(OriginValidator::allow_any())
            .require_authentication(true);

        // Without user
        let req = TestRequest::default().to_http_request();
        assert!(matches!(
            config.validate_upgrade(&req),
            Err(WebSocketSecurityError::Unauthorized)
        ));

        // With user
        let user = User::new("testuser".into(), "password".into());
        let req = create_request_with_user(user);
        assert!(config.validate_upgrade(&req).is_ok());
    }

    #[test]
    fn test_role_requirement() {
        let config = WebSocketSecurityConfig::new()
            .origin_validator(OriginValidator::allow_any())
            .required_roles(vec!["ADMIN".into()]);

        // User without required role
        let user = User::new("user".into(), "password".into()).roles(&["USER".into()]);
        let req = create_request_with_user(user);
        assert!(matches!(
            config.validate_upgrade(&req),
            Err(WebSocketSecurityError::MissingRole { .. })
        ));

        // User with required role
        let admin = User::new("admin".into(), "password".into()).roles(&["ADMIN".into()]);
        let req = create_request_with_user(admin);
        assert!(config.validate_upgrade(&req).is_ok());
    }

    #[test]
    fn test_authority_requirement() {
        let config = WebSocketSecurityConfig::new()
            .origin_validator(OriginValidator::allow_any())
            .required_authorities(vec!["ws:connect".into()]);

        // User without required authority
        let user = User::new("user".into(), "password".into());
        let req = create_request_with_user(user);
        assert!(matches!(
            config.validate_upgrade(&req),
            Err(WebSocketSecurityError::MissingAuthority { .. })
        ));

        // User with required authority
        let ws_user =
            User::new("user".into(), "password".into()).authorities(&["ws:connect".into()]);
        let req = create_request_with_user(ws_user);
        assert!(config.validate_upgrade(&req).is_ok());
    }

    #[test]
    fn test_combined_requirements() {
        let config = WebSocketSecurityConfig::new()
            .allowed_origins(vec!["https://myapp.com".into()])
            .required_roles(vec!["USER".into()])
            .required_authorities(vec!["ws:connect".into()]);

        // User with all requirements met
        let user = User::new("testuser".into(), "password".into())
            .roles(&["USER".into()])
            .authorities(&["ws:connect".into()]);

        let req = TestRequest::default()
            .insert_header(("origin", "https://myapp.com"))
            .to_http_request();
        req.extensions_mut().insert(user);

        assert!(config.validate_upgrade(&req).is_ok());
    }

    #[test]
    fn test_builder_pattern() {
        let config = WebSocketSecurityConfigBuilder::new()
            .allowed_origins(vec!["https://myapp.com".into()])
            .require_authentication()
            .required_roles(vec!["USER".into()])
            .build();

        let user = User::new("user".into(), "password".into()).roles(&["USER".into()]);
        let req = TestRequest::default()
            .insert_header(("origin", "https://myapp.com"))
            .to_http_request();
        req.extensions_mut().insert(user);

        assert!(config.validate_upgrade(&req).is_ok());
    }
}
