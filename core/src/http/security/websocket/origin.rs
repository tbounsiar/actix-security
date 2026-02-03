//! Origin validation for Cross-Site WebSocket Hijacking (CSWSH) prevention.
//!
//! # Cross-Site WebSocket Hijacking (CSWSH)
//!
//! CSWSH is an attack where a malicious website establishes a WebSocket connection
//! to your server using the victim's browser. Since browsers automatically include
//! cookies with WebSocket requests, the attacker can hijack authenticated sessions.
//!
//! ## Attack Scenario
//!
//! ```text
//! 1. User logs into https://yourapp.com (session cookie set)
//! 2. User visits https://evil.com
//! 3. evil.com runs: new WebSocket('wss://yourapp.com/ws')
//! 4. Browser includes yourapp.com cookies with the request!
//! 5. Without origin validation, attacker has authenticated WebSocket
//! ```
//!
//! ## Prevention
//!
//! Validate the `Origin` header to ensure WebSocket connections only come from
//! trusted origins (your own domains).
//!
//! # Usage
//!
//! ```ignore
//! use actix_security::http::security::websocket::OriginValidator;
//!
//! // Create validator with allowed origins
//! let validator = OriginValidator::new(&["https://myapp.com", "https://admin.myapp.com"]);
//!
//! // Validate a request
//! validator.validate(&req)?;
//!
//! // Or use the builder pattern
//! let validator = OriginValidator::builder()
//!     .allow("https://myapp.com")
//!     .allow("https://admin.myapp.com")
//!     .allow_localhost_in_dev(true)
//!     .build();
//! ```

use actix_web::HttpRequest;

use super::error::WebSocketSecurityError;

/// Validates the Origin header of WebSocket upgrade requests.
///
/// # Spring Security Equivalent
/// Spring's `StompSubProtocolErrorHandler` combined with `AllowedOriginPatterns`
///
/// # Example
///
/// ```ignore
/// use actix_security::http::security::websocket::OriginValidator;
///
/// let validator = OriginValidator::new(&["https://myapp.com"]);
///
/// #[get("/ws")]
/// async fn ws_handler(req: HttpRequest) -> Result<HttpResponse, Error> {
///     validator.validate(&req)?;
///     // ... upgrade to WebSocket
/// }
/// ```
#[derive(Debug, Clone, Default)]
pub struct OriginValidator {
    /// List of allowed origin patterns
    allowed_origins: Vec<String>,
    /// Allow any origin (dangerous - only for development)
    allow_any: bool,
    /// Allow missing origin header (not recommended)
    allow_missing: bool,
}

impl OriginValidator {
    /// Creates a new OriginValidator with the specified allowed origins.
    ///
    /// # Arguments
    /// * `origins` - List of allowed origin URLs (e.g., "https://myapp.com")
    ///
    /// # Example
    /// ```ignore
    /// let validator = OriginValidator::new(&["https://myapp.com", "https://api.myapp.com"]);
    /// ```
    pub fn new(origins: &[&str]) -> Self {
        Self {
            allowed_origins: origins.iter().map(|s| s.to_string()).collect(),
            allow_any: false,
            allow_missing: false,
        }
    }

    /// Creates a builder for more complex configuration.
    pub fn builder() -> OriginValidatorBuilder {
        OriginValidatorBuilder::default()
    }

    /// Creates a validator that allows any origin.
    ///
    /// # Warning
    /// This is dangerous and should only be used for development or when
    /// you have other authentication mechanisms in place.
    pub fn allow_any() -> Self {
        Self {
            allowed_origins: Vec::new(),
            allow_any: true,
            allow_missing: true,
        }
    }

    /// Validates the Origin header of the request.
    ///
    /// # Errors
    /// - `WebSocketSecurityError::MissingOrigin` - If Origin header is missing and `allow_missing` is false
    /// - `WebSocketSecurityError::InvalidOrigin` - If Origin is not in the allowed list
    pub fn validate(&self, req: &HttpRequest) -> Result<(), WebSocketSecurityError> {
        // Allow any origin if configured
        if self.allow_any {
            return Ok(());
        }

        // Extract Origin header
        let origin = req
            .headers()
            .get("origin")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        match origin {
            Some(origin) => {
                // Check if origin is allowed
                if self.is_allowed(&origin) {
                    Ok(())
                } else {
                    Err(WebSocketSecurityError::InvalidOrigin { origin })
                }
            }
            None => {
                if self.allow_missing {
                    Ok(())
                } else {
                    Err(WebSocketSecurityError::MissingOrigin)
                }
            }
        }
    }

    /// Checks if the given origin is in the allowed list.
    fn is_allowed(&self, origin: &str) -> bool {
        // Normalize origin (remove trailing slash)
        let normalized = origin.trim_end_matches('/');

        for allowed in &self.allowed_origins {
            let allowed_normalized = allowed.trim_end_matches('/');

            // Exact match
            if normalized.eq_ignore_ascii_case(allowed_normalized) {
                return true;
            }

            // Wildcard subdomain match (e.g., "*.myapp.com" matches "api.myapp.com")
            if let Some(pattern) = allowed_normalized.strip_prefix("*.") {
                if let Some(domain) = normalized.split("://").nth(1) {
                    if domain.ends_with(pattern) || domain == pattern {
                        return true;
                    }
                }
            }
        }

        false
    }
}

/// Builder for `OriginValidator`.
#[derive(Debug, Clone, Default)]
pub struct OriginValidatorBuilder {
    allowed_origins: Vec<String>,
    allow_any: bool,
    allow_missing: bool,
    allow_localhost_in_dev: bool,
}

impl OriginValidatorBuilder {
    /// Adds an allowed origin.
    ///
    /// # Example
    /// ```ignore
    /// let validator = OriginValidator::builder()
    ///     .allow("https://myapp.com")
    ///     .allow("https://admin.myapp.com")
    ///     .build();
    /// ```
    pub fn allow(mut self, origin: &str) -> Self {
        self.allowed_origins.push(origin.to_string());
        self
    }

    /// Adds multiple allowed origins.
    pub fn allow_all(mut self, origins: &[&str]) -> Self {
        self.allowed_origins
            .extend(origins.iter().map(|s| s.to_string()));
        self
    }

    /// Adds a wildcard pattern for subdomains.
    ///
    /// # Example
    /// ```ignore
    /// let validator = OriginValidator::builder()
    ///     .allow_subdomain_pattern("*.myapp.com")  // Matches api.myapp.com, admin.myapp.com, etc.
    ///     .build();
    /// ```
    pub fn allow_subdomain_pattern(mut self, pattern: &str) -> Self {
        if !pattern.starts_with("*.") {
            self.allowed_origins.push(format!("*.{}", pattern));
        } else {
            self.allowed_origins.push(pattern.to_string());
        }
        self
    }

    /// Allows any origin.
    ///
    /// # Warning
    /// This disables origin checking entirely. Only use for development or
    /// when you have other security measures in place.
    pub fn allow_any(mut self) -> Self {
        self.allow_any = true;
        self
    }

    /// Allows requests without an Origin header.
    ///
    /// # Warning
    /// Browsers always send an Origin header with WebSocket requests.
    /// Missing Origin usually indicates a non-browser client.
    pub fn allow_missing(mut self) -> Self {
        self.allow_missing = true;
        self
    }

    /// Allows localhost origins in debug builds.
    ///
    /// This adds `http://localhost:*` and `http://127.0.0.1:*` to allowed origins
    /// only when compiled in debug mode.
    pub fn allow_localhost_in_dev(mut self, allow: bool) -> Self {
        self.allow_localhost_in_dev = allow;
        self
    }

    /// Builds the `OriginValidator`.
    pub fn build(mut self) -> OriginValidator {
        // Add localhost in debug builds if requested
        #[cfg(debug_assertions)]
        if self.allow_localhost_in_dev {
            self.allowed_origins.push("http://localhost".to_string());
            self.allowed_origins.push("http://127.0.0.1".to_string());
            self.allowed_origins.push("http://localhost:*".to_string());
            self.allowed_origins.push("http://127.0.0.1:*".to_string());
        }

        OriginValidator {
            allowed_origins: self.allowed_origins,
            allow_any: self.allow_any,
            allow_missing: self.allow_missing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    #[test]
    fn test_exact_origin_match() {
        let validator = OriginValidator::new(&["https://myapp.com"]);

        let req = TestRequest::default()
            .insert_header(("origin", "https://myapp.com"))
            .to_http_request();

        assert!(validator.validate(&req).is_ok());
    }

    #[test]
    fn test_origin_case_insensitive() {
        let validator = OriginValidator::new(&["https://myapp.com"]);

        let req = TestRequest::default()
            .insert_header(("origin", "https://MYAPP.COM"))
            .to_http_request();

        assert!(validator.validate(&req).is_ok());
    }

    #[test]
    fn test_invalid_origin() {
        let validator = OriginValidator::new(&["https://myapp.com"]);

        let req = TestRequest::default()
            .insert_header(("origin", "https://evil.com"))
            .to_http_request();

        let result = validator.validate(&req);
        assert!(matches!(
            result,
            Err(WebSocketSecurityError::InvalidOrigin { origin }) if origin == "https://evil.com"
        ));
    }

    #[test]
    fn test_missing_origin_rejected() {
        let validator = OriginValidator::new(&["https://myapp.com"]);

        let req = TestRequest::default().to_http_request();

        assert!(matches!(
            validator.validate(&req),
            Err(WebSocketSecurityError::MissingOrigin)
        ));
    }

    #[test]
    fn test_missing_origin_allowed() {
        let validator = OriginValidator::builder()
            .allow("https://myapp.com")
            .allow_missing()
            .build();

        let req = TestRequest::default().to_http_request();

        assert!(validator.validate(&req).is_ok());
    }

    #[test]
    fn test_allow_any() {
        let validator = OriginValidator::allow_any();

        let req = TestRequest::default()
            .insert_header(("origin", "https://any-origin.com"))
            .to_http_request();

        assert!(validator.validate(&req).is_ok());
    }

    #[test]
    fn test_wildcard_subdomain() {
        let validator = OriginValidator::builder()
            .allow_subdomain_pattern("*.myapp.com")
            .build();

        // Should match subdomain
        let req = TestRequest::default()
            .insert_header(("origin", "https://api.myapp.com"))
            .to_http_request();
        assert!(validator.validate(&req).is_ok());

        // Should match another subdomain
        let req = TestRequest::default()
            .insert_header(("origin", "https://admin.myapp.com"))
            .to_http_request();
        assert!(validator.validate(&req).is_ok());

        // Should not match different domain
        let req = TestRequest::default()
            .insert_header(("origin", "https://evil.com"))
            .to_http_request();
        assert!(validator.validate(&req).is_err());
    }

    #[test]
    fn test_multiple_allowed_origins() {
        let validator = OriginValidator::builder()
            .allow("https://myapp.com")
            .allow("https://api.myapp.com")
            .allow("https://admin.myapp.com")
            .build();

        for origin in [
            "https://myapp.com",
            "https://api.myapp.com",
            "https://admin.myapp.com",
        ] {
            let req = TestRequest::default()
                .insert_header(("origin", origin))
                .to_http_request();
            assert!(validator.validate(&req).is_ok());
        }
    }

    #[test]
    fn test_trailing_slash_normalization() {
        let validator = OriginValidator::new(&["https://myapp.com/"]);

        let req = TestRequest::default()
            .insert_header(("origin", "https://myapp.com"))
            .to_http_request();

        assert!(validator.validate(&req).is_ok());
    }
}
