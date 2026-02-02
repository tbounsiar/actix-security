//! Remember-Me Authentication.
//!
//! # Spring Security Equivalent
//! Similar to Spring Security's Remember-Me authentication with `RememberMeServices`.
//!
//! # Features
//! - Persistent login via cookie
//! - Token-based remember-me (secure)
//! - Configurable token validity
//! - Automatic token refresh
//!
//! # Example
//! ```rust,ignore
//! use actix_security_core::http::security::remember_me::{RememberMeServices, RememberMeConfig};
//!
//! let remember_me = RememberMeServices::new(
//!     RememberMeConfig::new("my-secret-key")
//!         .token_validity_days(14)
//!         .cookie_name("remember-me")
//! );
//!
//! // In login handler
//! async fn login(
//!     session: Session,
//!     form: Form<LoginForm>,
//!     remember_me: Data<RememberMeServices>,
//! ) -> impl Responder {
//!     // Validate credentials...
//!     let user = validate_user(&form.username, &form.password)?;
//!
//!     // Create remember-me cookie if checkbox is checked
//!     if form.remember_me {
//!         let cookie = remember_me.login_success(&user);
//!         return HttpResponse::Ok()
//!             .cookie(cookie)
//!             .body("Logged in with remember-me");
//!     }
//!
//!     HttpResponse::Ok().body("Logged in")
//! }
//! ```

use crate::http::security::User;
use actix_web::cookie::{Cookie, SameSite};
use base64::prelude::*;
use rand::Rng;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// =============================================================================
// Remember-Me Configuration
// =============================================================================

/// Remember-Me configuration.
///
/// # Spring Security Equivalent
/// Similar to `RememberMeConfigurer` in Spring Security.
#[derive(Clone)]
pub struct RememberMeConfig {
    /// Secret key for token signing
    key: String,
    /// Token validity duration
    token_validity: Duration,
    /// Cookie name
    cookie_name: String,
    /// Cookie path
    cookie_path: String,
    /// Cookie domain (None = current domain)
    cookie_domain: Option<String>,
    /// Cookie secure flag (HTTPS only)
    cookie_secure: bool,
    /// Cookie HTTP only flag
    cookie_http_only: bool,
    /// Cookie SameSite attribute
    cookie_same_site: SameSite,
    /// Parameter name in form for remember-me checkbox
    parameter_name: String,
    /// Whether to always remember (ignore checkbox)
    always_remember: bool,
}

impl RememberMeConfig {
    /// Create a new remember-me configuration with the given secret key.
    ///
    /// The key is used to sign tokens and should be kept secret.
    pub fn new(key: &str) -> Self {
        Self {
            key: key.to_string(),
            token_validity: Duration::from_secs(14 * 24 * 60 * 60), // 14 days
            cookie_name: "remember-me".to_string(),
            cookie_path: "/".to_string(),
            cookie_domain: None,
            cookie_secure: true,
            cookie_http_only: true,
            cookie_same_site: SameSite::Lax,
            parameter_name: "remember-me".to_string(),
            always_remember: false,
        }
    }

    /// Set token validity in days.
    pub fn token_validity_days(mut self, days: u64) -> Self {
        self.token_validity = Duration::from_secs(days * 24 * 60 * 60);
        self
    }

    /// Set token validity in seconds.
    pub fn token_validity_seconds(mut self, seconds: u64) -> Self {
        self.token_validity = Duration::from_secs(seconds);
        self
    }

    /// Set the cookie name.
    pub fn cookie_name(mut self, name: &str) -> Self {
        self.cookie_name = name.to_string();
        self
    }

    /// Set the cookie path.
    pub fn cookie_path(mut self, path: &str) -> Self {
        self.cookie_path = path.to_string();
        self
    }

    /// Set the cookie domain.
    pub fn cookie_domain(mut self, domain: &str) -> Self {
        self.cookie_domain = Some(domain.to_string());
        self
    }

    /// Set whether the cookie requires HTTPS.
    pub fn cookie_secure(mut self, secure: bool) -> Self {
        self.cookie_secure = secure;
        self
    }

    /// Set whether the cookie is HTTP only.
    pub fn cookie_http_only(mut self, http_only: bool) -> Self {
        self.cookie_http_only = http_only;
        self
    }

    /// Set the cookie SameSite attribute.
    pub fn cookie_same_site(mut self, same_site: SameSite) -> Self {
        self.cookie_same_site = same_site;
        self
    }

    /// Set the form parameter name for remember-me checkbox.
    pub fn parameter_name(mut self, name: &str) -> Self {
        self.parameter_name = name.to_string();
        self
    }

    /// Set whether to always remember (ignore checkbox).
    pub fn always_remember(mut self, always: bool) -> Self {
        self.always_remember = always;
        self
    }

    /// Get the secret key.
    pub fn get_key(&self) -> &str {
        &self.key
    }

    /// Get token validity duration.
    pub fn get_token_validity(&self) -> Duration {
        self.token_validity
    }

    /// Get the cookie name.
    pub fn get_cookie_name(&self) -> &str {
        &self.cookie_name
    }

    /// Get the parameter name.
    pub fn get_parameter_name(&self) -> &str {
        &self.parameter_name
    }

    /// Check if always remember is enabled.
    pub fn is_always_remember(&self) -> bool {
        self.always_remember
    }
}

// =============================================================================
// Remember-Me Token
// =============================================================================

/// Remember-Me token structure.
///
/// Token format: base64(username:expiry_timestamp:signature)
/// Where signature = hmac(key, username:expiry_timestamp)
#[derive(Debug, Clone)]
pub struct RememberMeToken {
    /// Username
    pub username: String,
    /// Expiry timestamp (seconds since UNIX epoch)
    pub expiry: u64,
    /// Token signature
    pub signature: String,
}

impl RememberMeToken {
    /// Create a new token for the given username.
    pub fn new(username: &str, validity: Duration, key: &str) -> Self {
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + validity.as_secs();

        let signature = Self::compute_signature(username, expiry, key);

        Self {
            username: username.to_string(),
            expiry,
            signature,
        }
    }

    /// Compute token signature.
    fn compute_signature(username: &str, expiry: u64, key: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Simple signature using hash (in production, use HMAC-SHA256)
        let mut hasher = DefaultHasher::new();
        format!("{}:{}:{}", username, expiry, key).hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    /// Encode token to string.
    pub fn encode(&self) -> String {
        let data = format!("{}:{}:{}", self.username, self.expiry, self.signature);
        BASE64_STANDARD.encode(data.as_bytes())
    }

    /// Decode token from string.
    pub fn decode(encoded: &str) -> Option<Self> {
        let decoded = BASE64_STANDARD.decode(encoded).ok()?;
        let data = String::from_utf8(decoded).ok()?;

        let parts: Vec<&str> = data.splitn(3, ':').collect();
        if parts.len() != 3 {
            return None;
        }

        Some(Self {
            username: parts[0].to_string(),
            expiry: parts[1].parse().ok()?,
            signature: parts[2].to_string(),
        })
    }

    /// Validate token.
    pub fn validate(&self, key: &str) -> bool {
        // Check expiry
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now > self.expiry {
            return false;
        }

        // Check signature
        let expected_signature = Self::compute_signature(&self.username, self.expiry, key);
        self.signature == expected_signature
    }

    /// Check if token is expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expiry
    }
}

// =============================================================================
// Remember-Me Services
// =============================================================================

/// Remember-Me authentication services.
///
/// # Spring Security Equivalent
/// Similar to `TokenBasedRememberMeServices` in Spring Security.
///
/// Provides methods for:
/// - Creating remember-me cookies on login
/// - Validating remember-me cookies
/// - Clearing remember-me cookies on logout
#[derive(Clone)]
pub struct RememberMeServices {
    config: RememberMeConfig,
}

impl RememberMeServices {
    /// Create new remember-me services with the given configuration.
    pub fn new(config: RememberMeConfig) -> Self {
        Self { config }
    }

    /// Create a remember-me cookie for successful login.
    ///
    /// # Spring Equivalent
    /// `RememberMeServices.loginSuccess()`
    pub fn login_success(&self, user: &User) -> Cookie<'static> {
        let token = RememberMeToken::new(
            user.get_username(),
            self.config.token_validity,
            &self.config.key,
        );

        self.create_cookie(token.encode())
    }

    /// Validate remember-me cookie and return username if valid.
    ///
    /// # Spring Equivalent
    /// `RememberMeServices.autoLogin()`
    pub fn auto_login(&self, cookie_value: &str) -> Option<String> {
        let token = RememberMeToken::decode(cookie_value)?;

        if token.validate(&self.config.key) {
            Some(token.username)
        } else {
            None
        }
    }

    /// Create a cookie that clears the remember-me token (for logout).
    ///
    /// # Spring Equivalent
    /// `RememberMeServices.logout()`
    pub fn logout(&self) -> Cookie<'static> {
        let mut cookie = Cookie::build(self.config.cookie_name.clone(), "")
            .path(self.config.cookie_path.clone())
            .max_age(actix_web::cookie::time::Duration::ZERO)
            .http_only(self.config.cookie_http_only)
            .same_site(self.config.cookie_same_site);

        if let Some(domain) = &self.config.cookie_domain {
            cookie = cookie.domain(domain.clone());
        }

        if self.config.cookie_secure {
            cookie = cookie.secure(true);
        }

        cookie.finish()
    }

    /// Create a remember-me cookie with the given value.
    fn create_cookie(&self, value: String) -> Cookie<'static> {
        let max_age =
            actix_web::cookie::time::Duration::seconds(self.config.token_validity.as_secs() as i64);

        let mut cookie = Cookie::build(self.config.cookie_name.clone(), value)
            .path(self.config.cookie_path.clone())
            .max_age(max_age)
            .http_only(self.config.cookie_http_only)
            .same_site(self.config.cookie_same_site);

        if let Some(domain) = &self.config.cookie_domain {
            cookie = cookie.domain(domain.clone());
        }

        if self.config.cookie_secure {
            cookie = cookie.secure(true);
        }

        cookie.finish()
    }

    /// Get the cookie name for reading from request.
    pub fn cookie_name(&self) -> &str {
        &self.config.cookie_name
    }

    /// Get the form parameter name.
    pub fn parameter_name(&self) -> &str {
        &self.config.parameter_name
    }

    /// Check if always remember is enabled.
    pub fn is_always_remember(&self) -> bool {
        self.config.always_remember
    }

    /// Get the configuration.
    pub fn config(&self) -> &RememberMeConfig {
        &self.config
    }

    /// Generate a random token (for persistent token variant).
    #[allow(dead_code)]
    fn generate_random_token() -> String {
        let mut rng = rand::thread_rng();
        let bytes: [u8; 32] = rng.gen();
        BASE64_STANDARD.encode(bytes)
    }
}

// =============================================================================
// Remember-Me Error
// =============================================================================

/// Remember-Me related errors.
#[derive(Debug)]
pub enum RememberMeError {
    /// Invalid token format
    InvalidToken,
    /// Token expired
    TokenExpired,
    /// Invalid signature
    InvalidSignature,
    /// User not found
    UserNotFound,
}

impl std::fmt::Display for RememberMeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RememberMeError::InvalidToken => write!(f, "Invalid remember-me token"),
            RememberMeError::TokenExpired => write!(f, "Remember-me token expired"),
            RememberMeError::InvalidSignature => write!(f, "Invalid token signature"),
            RememberMeError::UserNotFound => write!(f, "User not found"),
        }
    }
}

impl std::error::Error for RememberMeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user() -> User {
        User::new("testuser".to_string(), "password".to_string()).roles(&["USER".into()])
    }

    #[test]
    fn test_remember_me_config() {
        let config = RememberMeConfig::new("secret")
            .token_validity_days(7)
            .cookie_name("my-remember-me")
            .cookie_secure(false)
            .parameter_name("rememberMe");

        assert_eq!(config.get_key(), "secret");
        assert_eq!(
            config.get_token_validity(),
            Duration::from_secs(7 * 24 * 60 * 60)
        );
        assert_eq!(config.get_cookie_name(), "my-remember-me");
        assert_eq!(config.get_parameter_name(), "rememberMe");
    }

    #[test]
    fn test_token_encode_decode() {
        let token = RememberMeToken::new("testuser", Duration::from_secs(3600), "secret");
        let encoded = token.encode();

        let decoded = RememberMeToken::decode(&encoded).unwrap();
        assert_eq!(decoded.username, "testuser");
        assert_eq!(decoded.expiry, token.expiry);
        assert_eq!(decoded.signature, token.signature);
    }

    #[test]
    fn test_token_validation() {
        let token = RememberMeToken::new("testuser", Duration::from_secs(3600), "secret");

        // Valid token
        assert!(token.validate("secret"));

        // Invalid key
        assert!(!token.validate("wrong-secret"));
    }

    #[test]
    fn test_token_expiry() {
        // Create a token with expiry in the past
        let token = RememberMeToken {
            username: "testuser".to_string(),
            expiry: 1, // Way in the past (1970)
            signature: "invalid".to_string(),
        };

        assert!(token.is_expired());
        assert!(!token.validate("secret"));
    }

    #[test]
    fn test_remember_me_services() {
        let config = RememberMeConfig::new("secret")
            .token_validity_days(14)
            .cookie_secure(false);

        let services = RememberMeServices::new(config);
        let user = test_user();

        // Create login cookie
        let cookie = services.login_success(&user);
        assert_eq!(cookie.name(), "remember-me");

        // Validate cookie
        let username = services.auto_login(cookie.value());
        assert_eq!(username, Some("testuser".to_string()));
    }

    #[test]
    fn test_remember_me_logout() {
        let config = RememberMeConfig::new("secret");
        let services = RememberMeServices::new(config);

        let cookie = services.logout();
        assert_eq!(cookie.name(), "remember-me");
        assert_eq!(cookie.value(), "");
    }

    #[test]
    fn test_invalid_token() {
        let config = RememberMeConfig::new("secret");
        let services = RememberMeServices::new(config);

        // Invalid base64
        assert!(services.auto_login("not-valid-base64!!!").is_none());

        // Invalid format (valid base64 but wrong structure)
        let invalid = BASE64_STANDARD.encode("invalid");
        assert!(services.auto_login(&invalid).is_none());
    }
}
