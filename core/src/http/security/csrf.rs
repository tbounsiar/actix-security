//! CSRF (Cross-Site Request Forgery) Protection.
//!
//! # Spring Security Equivalent
//! Similar to Spring Security's CSRF protection with `CsrfFilter`.
//!
//! # Features
//! - Token-based CSRF protection
//! - Session or cookie-based token storage
//! - Configurable ignored paths and methods
//! - Integration with form submissions and AJAX requests
//!
//! # Example
//! ```rust,ignore
//! use actix_security_core::http::security::csrf::{CsrfProtection, CsrfConfig};
//!
//! // Create CSRF protection middleware
//! let csrf = CsrfProtection::new(CsrfConfig::default());
//!
//! App::new()
//!     .wrap(session_middleware)
//!     .wrap(csrf)  // Add CSRF protection
//!     .wrap(security_transform)
//!
//! // In templates, include the CSRF token
//! // <input type="hidden" name="_csrf" value="{{csrf_token}}">
//!
//! // For AJAX, send the token in a header
//! // X-CSRF-TOKEN: {{csrf_token}}
//! ```

use actix_session::SessionExt;
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::Method;
use actix_web::{body::EitherBody, Error, HttpMessage, HttpResponse};
use futures_util::future::{ok, LocalBoxFuture, Ready};
use rand::Rng;
use regex::Regex;
use std::rc::Rc;
use std::sync::Arc;

// =============================================================================
// CSRF Token
// =============================================================================

/// CSRF Token.
///
/// # Spring Security Equivalent
/// Similar to `CsrfToken` in Spring Security.
#[derive(Debug, Clone)]
pub struct CsrfToken {
    /// The token value
    pub token: String,
    /// Header name for AJAX requests
    pub header_name: String,
    /// Parameter name for form submissions
    pub parameter_name: String,
}

impl CsrfToken {
    /// Create a new CSRF token with the given value.
    pub fn new(token: String) -> Self {
        Self {
            token,
            header_name: "X-CSRF-TOKEN".to_string(),
            parameter_name: "_csrf".to_string(),
        }
    }

    /// Create with custom header and parameter names.
    pub fn with_names(token: String, header_name: &str, parameter_name: &str) -> Self {
        Self {
            token,
            header_name: header_name.to_string(),
            parameter_name: parameter_name.to_string(),
        }
    }

    /// Get the token value.
    pub fn value(&self) -> &str {
        &self.token
    }

    /// Get the header name.
    pub fn header_name(&self) -> &str {
        &self.header_name
    }

    /// Get the parameter name.
    pub fn parameter_name(&self) -> &str {
        &self.parameter_name
    }
}

// =============================================================================
// CSRF Token Repository Trait
// =============================================================================

/// Trait for storing and retrieving CSRF tokens.
///
/// # Spring Security Equivalent
/// Similar to `CsrfTokenRepository` in Spring Security.
pub trait CsrfTokenRepository: Send + Sync {
    /// Generate a new CSRF token.
    fn generate_token(&self) -> CsrfToken;

    /// Save token to storage.
    fn save_token(&self, req: &ServiceRequest, token: &CsrfToken) -> Result<(), CsrfError>;

    /// Load token from storage.
    fn load_token(&self, req: &ServiceRequest) -> Option<CsrfToken>;
}

// =============================================================================
// Session CSRF Token Repository
// =============================================================================

/// Session-based CSRF token repository.
///
/// Stores the CSRF token in the user's session.
///
/// # Spring Security Equivalent
/// Similar to `HttpSessionCsrfTokenRepository` in Spring Security.
#[derive(Clone)]
pub struct SessionCsrfTokenRepository {
    /// Session key for storing the token
    session_key: String,
    /// Header name for the token
    header_name: String,
    /// Parameter name for the token
    parameter_name: String,
}

impl Default for SessionCsrfTokenRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionCsrfTokenRepository {
    /// Create a new session-based repository.
    pub fn new() -> Self {
        Self {
            session_key: "CSRF_TOKEN".to_string(),
            header_name: "X-CSRF-TOKEN".to_string(),
            parameter_name: "_csrf".to_string(),
        }
    }

    /// Set the session key.
    pub fn session_key(mut self, key: &str) -> Self {
        self.session_key = key.to_string();
        self
    }

    /// Set the header name.
    pub fn header_name(mut self, name: &str) -> Self {
        self.header_name = name.to_string();
        self
    }

    /// Set the parameter name.
    pub fn parameter_name(mut self, name: &str) -> Self {
        self.parameter_name = name.to_string();
        self
    }

    /// Generate a random token value.
    fn generate_token_value(&self) -> String {
        let mut rng = rand::thread_rng();
        let bytes: [u8; 32] = rng.gen();
        hex::encode(&bytes)
    }
}

impl CsrfTokenRepository for SessionCsrfTokenRepository {
    fn generate_token(&self) -> CsrfToken {
        CsrfToken::with_names(
            self.generate_token_value(),
            &self.header_name,
            &self.parameter_name,
        )
    }

    fn save_token(&self, req: &ServiceRequest, token: &CsrfToken) -> Result<(), CsrfError> {
        let session = req.get_session();
        session
            .insert(&self.session_key, &token.token)
            .map_err(|e| CsrfError::StorageError(e.to_string()))
    }

    fn load_token(&self, req: &ServiceRequest) -> Option<CsrfToken> {
        let session = req.get_session();
        session
            .get::<String>(&self.session_key)
            .ok()
            .flatten()
            .map(|token| CsrfToken::with_names(token, &self.header_name, &self.parameter_name))
    }
}

// =============================================================================
// CSRF Configuration
// =============================================================================

/// CSRF protection configuration.
///
/// # Spring Security Equivalent
/// Similar to `CsrfConfigurer` in Spring Security.
#[derive(Clone)]
pub struct CsrfConfig {
    /// Token repository
    repository: Arc<dyn CsrfTokenRepository>,
    /// Methods that require CSRF protection
    protected_methods: Vec<Method>,
    /// Paths to ignore (regex patterns)
    ignored_paths: Vec<Regex>,
    /// Header name for the token
    header_name: String,
    /// Parameter name for the token
    parameter_name: String,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl CsrfConfig {
    /// Create a new CSRF configuration with default settings.
    ///
    /// By default:
    /// - Uses session-based token storage
    /// - Protects POST, PUT, DELETE, PATCH methods
    /// - Token header: X-CSRF-TOKEN
    /// - Token parameter: _csrf
    pub fn new() -> Self {
        Self {
            repository: Arc::new(SessionCsrfTokenRepository::new()),
            protected_methods: vec![Method::POST, Method::PUT, Method::DELETE, Method::PATCH],
            ignored_paths: Vec::new(),
            header_name: "X-CSRF-TOKEN".to_string(),
            parameter_name: "_csrf".to_string(),
        }
    }

    /// Set a custom token repository.
    pub fn repository<R: CsrfTokenRepository + 'static>(mut self, repository: R) -> Self {
        self.repository = Arc::new(repository);
        self
    }

    /// Set the methods that require CSRF protection.
    pub fn protected_methods(mut self, methods: Vec<Method>) -> Self {
        self.protected_methods = methods;
        self
    }

    /// Add a path pattern to ignore.
    ///
    /// # Example
    /// ```rust,ignore
    /// let config = CsrfConfig::new()
    ///     .ignore_path("/api/.*")  // Ignore all API paths
    ///     .ignore_path("/webhook");
    /// ```
    pub fn ignore_path(mut self, pattern: &str) -> Self {
        if let Ok(regex) = Regex::new(pattern) {
            self.ignored_paths.push(regex);
        }
        self
    }

    /// Set the header name for the token.
    pub fn header_name(mut self, name: &str) -> Self {
        self.header_name = name.to_string();
        self
    }

    /// Set the parameter name for the token.
    pub fn parameter_name(mut self, name: &str) -> Self {
        self.parameter_name = name.to_string();
        self
    }

    /// Check if a path should be ignored.
    fn is_path_ignored(&self, path: &str) -> bool {
        self.ignored_paths.iter().any(|regex| regex.is_match(path))
    }

    /// Check if a method requires CSRF protection.
    fn requires_protection(&self, method: &Method) -> bool {
        self.protected_methods.contains(method)
    }
}

// =============================================================================
// CSRF Protection Middleware
// =============================================================================

/// CSRF protection middleware.
///
/// # Spring Security Equivalent
/// Similar to `CsrfFilter` in Spring Security.
///
/// # Behavior
/// 1. For safe methods (GET, HEAD, OPTIONS, TRACE): Generate and store token
/// 2. For state-changing methods (POST, PUT, DELETE, PATCH): Validate token
/// 3. Token is available in request extensions as `CsrfToken`
///
/// # Example
/// ```rust,ignore
/// use actix_security_core::http::security::csrf::{CsrfProtection, CsrfConfig};
///
/// App::new()
///     .wrap(CsrfProtection::new(CsrfConfig::default()))
/// ```
#[derive(Clone)]
pub struct CsrfProtection {
    config: CsrfConfig,
}

impl CsrfProtection {
    /// Create new CSRF protection with the given configuration.
    pub fn new(config: CsrfConfig) -> Self {
        Self { config }
    }

    /// Create with default configuration.
    pub fn default_config() -> Self {
        Self::new(CsrfConfig::default())
    }
}

impl<S, B> Transform<S, ServiceRequest> for CsrfProtection
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = CsrfMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(CsrfMiddleware {
            service: Rc::new(service),
            config: self.config.clone(),
        })
    }
}

/// CSRF middleware service.
pub struct CsrfMiddleware<S> {
    service: Rc<S>,
    config: CsrfConfig,
}

impl<S, B> Service<ServiceRequest> for CsrfMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let config = self.config.clone();

        Box::pin(async move {
            let path = req.path().to_string();
            let method = req.method().clone();

            // Check if path is ignored
            if config.is_path_ignored(&path) {
                let res = service.call(req).await?;
                return Ok(res.map_into_left_body());
            }

            // Load or generate token
            let token = match config.repository.load_token(&req) {
                Some(token) => token,
                None => {
                    let token = config.repository.generate_token();
                    let _ = config.repository.save_token(&req, &token);
                    token
                }
            };

            // Store token in request extensions for handlers to use
            req.extensions_mut().insert(token.clone());

            // Check if method requires CSRF validation
            if config.requires_protection(&method) {
                // Get token from request (header or parameter)
                let request_token = get_token_from_request(&req, &config);

                match request_token {
                    Some(submitted_token) if submitted_token == token.token => {
                        // Token valid, proceed
                        let res = service.call(req).await?;
                        Ok(res.map_into_left_body())
                    }
                    Some(_) => {
                        // Token mismatch
                        let response = HttpResponse::Forbidden()
                            .body("CSRF token mismatch")
                            .map_into_right_body();
                        Ok(req.into_response(response))
                    }
                    None => {
                        // No token provided
                        let response = HttpResponse::Forbidden()
                            .body("CSRF token missing")
                            .map_into_right_body();
                        Ok(req.into_response(response))
                    }
                }
            } else {
                // Safe method, no validation needed
                let res = service.call(req).await?;
                Ok(res.map_into_left_body())
            }
        })
    }
}

/// Extract CSRF token from request (header or query parameter).
fn get_token_from_request(req: &ServiceRequest, config: &CsrfConfig) -> Option<String> {
    // Try header first
    if let Some(header_value) = req.headers().get(&config.header_name) {
        if let Ok(token) = header_value.to_str() {
            return Some(token.to_string());
        }
    }

    // Try query string
    let query_string = req.query_string();
    let param_prefix = format!("{}=", config.parameter_name);
    for pair in query_string.split('&') {
        if pair.starts_with(&param_prefix) {
            return Some(pair[param_prefix.len()..].to_string());
        }
    }

    None
}

// =============================================================================
// CSRF Error
// =============================================================================

/// CSRF-related errors.
#[derive(Debug)]
pub enum CsrfError {
    /// Missing CSRF token
    MissingToken,
    /// Invalid CSRF token
    InvalidToken,
    /// Token mismatch
    TokenMismatch,
    /// Storage error
    StorageError(String),
}

impl std::fmt::Display for CsrfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CsrfError::MissingToken => write!(f, "CSRF token missing"),
            CsrfError::InvalidToken => write!(f, "Invalid CSRF token"),
            CsrfError::TokenMismatch => write!(f, "CSRF token mismatch"),
            CsrfError::StorageError(e) => write!(f, "CSRF storage error: {}", e),
        }
    }
}

impl std::error::Error for CsrfError {}

// =============================================================================
// Helper for hex encoding (simple implementation)
// =============================================================================

mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(bytes: &[u8]) -> String {
        let mut result = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            result.push(HEX_CHARS[(byte >> 4) as usize] as char);
            result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csrf_token() {
        let token = CsrfToken::new("test-token".to_string());
        assert_eq!(token.value(), "test-token");
        assert_eq!(token.header_name(), "X-CSRF-TOKEN");
        assert_eq!(token.parameter_name(), "_csrf");
    }

    #[test]
    fn test_csrf_token_custom_names() {
        let token = CsrfToken::with_names(
            "test-token".to_string(),
            "X-Custom-CSRF",
            "csrf_token",
        );
        assert_eq!(token.header_name(), "X-Custom-CSRF");
        assert_eq!(token.parameter_name(), "csrf_token");
    }

    #[test]
    fn test_csrf_config_default() {
        let config = CsrfConfig::default();
        assert_eq!(config.header_name, "X-CSRF-TOKEN");
        assert_eq!(config.parameter_name, "_csrf");
        assert!(config.protected_methods.contains(&Method::POST));
        assert!(config.protected_methods.contains(&Method::PUT));
        assert!(config.protected_methods.contains(&Method::DELETE));
        assert!(config.protected_methods.contains(&Method::PATCH));
        assert!(!config.protected_methods.contains(&Method::GET));
    }

    #[test]
    fn test_csrf_config_ignore_path() {
        let config = CsrfConfig::new()
            .ignore_path("/api/.*")
            .ignore_path("/webhook");

        assert!(config.is_path_ignored("/api/users"));
        assert!(config.is_path_ignored("/api/posts/123"));
        assert!(config.is_path_ignored("/webhook"));
        assert!(!config.is_path_ignored("/admin"));
    }

    #[test]
    fn test_csrf_config_protected_methods() {
        let config = CsrfConfig::new()
            .protected_methods(vec![Method::POST]);

        assert!(config.requires_protection(&Method::POST));
        assert!(!config.requires_protection(&Method::PUT));
        assert!(!config.requires_protection(&Method::GET));
    }

    #[test]
    fn test_session_csrf_repository() {
        let repo = SessionCsrfTokenRepository::new()
            .session_key("MY_CSRF")
            .header_name("X-My-CSRF")
            .parameter_name("my_csrf");

        let token = repo.generate_token();
        assert_eq!(token.header_name(), "X-My-CSRF");
        assert_eq!(token.parameter_name(), "my_csrf");
        assert_eq!(token.token.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex::encode(&[0x00]), "00");
        assert_eq!(hex::encode(&[0xff]), "ff");
        assert_eq!(hex::encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }
}
