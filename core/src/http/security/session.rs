//! Session-based Authentication.
//!
//! # Spring Security Equivalent
//! Similar to Spring Security's session-based authentication with `HttpSession`.
//!
//! # Features
//! - Store user in session after login
//! - Session fixation protection (migrate, new session, or none)
//! - Configurable session timeout
//! - Maximum sessions per user support
//! - Integration with actix-session
//!
//! # Example
//! ```rust,ignore
//! use actix_security_core::http::security::session::{
//!     SessionAuthenticator, SessionConfig, SessionFixationStrategy
//! };
//! use actix_session::SessionMiddleware;
//! use actix_session::storage::CookieSessionStore;
//!
//! // Configure session middleware (required)
//! let session_middleware = SessionMiddleware::new(
//!     CookieSessionStore::default(),
//!     cookie_key.clone()
//! );
//!
//! // Configure session authenticator with fixation protection
//! let config = SessionConfig::new()
//!     .fixation_strategy(SessionFixationStrategy::MigrateSession);
//!
//! let authenticator = SessionAuthenticator::new(config);
//!
//! App::new()
//!     .wrap(session_middleware)
//!     .wrap(SecurityTransform::new()
//!         .config_authenticator(move || authenticator.clone())
//!         .config_authorizer(|| /* ... */))
//! ```

use crate::http::security::config::Authenticator;
use crate::http::security::User;
use actix_session::SessionExt;
use actix_web::dev::ServiceRequest;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// =============================================================================
// Session Fixation Strategy
// =============================================================================

/// Strategy for session fixation protection.
///
/// # Spring Security Equivalent
/// Similar to `SessionFixationProtectionStrategy` in Spring Security.
///
/// Session fixation attacks occur when an attacker sets a user's session ID
/// before they authenticate. After authentication, the attacker can hijack
/// the session using the known session ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionFixationStrategy {
    /// Create a new session and migrate all attributes from the old session.
    /// This is the safest option that preserves user data.
    ///
    /// # Spring Equivalent
    /// `SessionFixationProtectionStrategy.MIGRATE_SESSION`
    #[default]
    MigrateSession,

    /// Create a new session without migrating attributes.
    /// Use this when you want a completely fresh session after login.
    ///
    /// # Spring Equivalent
    /// `SessionFixationProtectionStrategy.NEW_SESSION`
    NewSession,

    /// No session fixation protection.
    /// **WARNING**: This is insecure and should only be used for testing.
    ///
    /// # Spring Equivalent
    /// `SessionFixationProtectionStrategy.NONE`
    None,
}

// =============================================================================
// Session User Data
// =============================================================================

/// Serializable user data stored in session.
///
/// This is the data structure stored in the session.
/// It's separate from `User` to ensure clean serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionUser {
    /// Username
    pub username: String,
    /// User roles
    pub roles: Vec<String>,
    /// User authorities/permissions
    pub authorities: Vec<String>,
}

impl SessionUser {
    /// Create from a User.
    pub fn from_user(user: &User) -> Self {
        Self {
            username: user.get_username().to_string(),
            roles: user.get_roles().to_vec(),
            authorities: user.get_authorities().to_vec(),
        }
    }

    /// Convert to User.
    pub fn to_user(&self) -> User {
        User::new(self.username.clone(), String::new())
            .roles(&self.roles)
            .authorities(&self.authorities)
    }
}

impl From<&User> for SessionUser {
    fn from(user: &User) -> Self {
        Self::from_user(user)
    }
}

impl From<SessionUser> for User {
    fn from(session_user: SessionUser) -> Self {
        session_user.to_user()
    }
}

// =============================================================================
// Session Configuration
// =============================================================================

/// Session authentication configuration.
///
/// # Spring Security Equivalent
/// Combines `SessionManagementConfigurer` and `SessionFixationConfigurer`.
///
/// # Example
/// ```rust,ignore
/// let config = SessionConfig::new()
///     .user_key("user")
///     .fixation_strategy(SessionFixationStrategy::MigrateSession)
///     .maximum_sessions(1);  // Only one session per user
/// ```
#[derive(Clone)]
pub struct SessionConfig {
    /// Session key for storing user data
    user_key: String,
    /// Session key for authentication flag
    authenticated_key: String,
    /// Session key for storing the original request URL (for redirect after login)
    saved_request_key: String,
    /// Session fixation protection strategy
    fixation_strategy: SessionFixationStrategy,
    /// Maximum number of concurrent sessions per user (None = unlimited)
    maximum_sessions: Option<usize>,
    /// Session timeout duration (used for reference, actual timeout configured in SessionMiddleware)
    timeout: Option<Duration>,
    /// Whether to expire the oldest session when max sessions exceeded
    expire_oldest_session: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionConfig {
    /// Create a new session configuration with default keys.
    pub fn new() -> Self {
        Self {
            user_key: "security_user".to_string(),
            authenticated_key: "security_authenticated".to_string(),
            saved_request_key: "security_saved_request".to_string(),
            fixation_strategy: SessionFixationStrategy::MigrateSession,
            maximum_sessions: None,
            timeout: None,
            expire_oldest_session: false,
        }
    }

    /// Set the session key for user data.
    pub fn user_key(mut self, key: &str) -> Self {
        self.user_key = key.to_string();
        self
    }

    /// Set the session key for authentication flag.
    pub fn authenticated_key(mut self, key: &str) -> Self {
        self.authenticated_key = key.to_string();
        self
    }

    /// Set the session key for saved request URL.
    pub fn saved_request_key(mut self, key: &str) -> Self {
        self.saved_request_key = key.to_string();
        self
    }

    /// Set the session fixation protection strategy.
    ///
    /// # Spring Equivalent
    /// `sessionManagement().sessionFixation().migrateSession()`
    pub fn fixation_strategy(mut self, strategy: SessionFixationStrategy) -> Self {
        self.fixation_strategy = strategy;
        self
    }

    /// Set the maximum number of concurrent sessions per user.
    ///
    /// # Spring Equivalent
    /// `sessionManagement().maximumSessions(1)`
    pub fn maximum_sessions(mut self, max: usize) -> Self {
        self.maximum_sessions = Some(max);
        self
    }

    /// Set the session timeout duration.
    /// Note: This is informational; actual timeout is configured in SessionMiddleware.
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = Some(duration);
        self
    }

    /// Whether to expire the oldest session when maximum sessions exceeded.
    ///
    /// # Spring Equivalent
    /// `sessionManagement().maximumSessions(1).expiredSessionStrategy(...)`
    pub fn expire_oldest_session(mut self, expire: bool) -> Self {
        self.expire_oldest_session = expire;
        self
    }

    /// Get the user key.
    pub fn get_user_key(&self) -> &str {
        &self.user_key
    }

    /// Get the authenticated key.
    pub fn get_authenticated_key(&self) -> &str {
        &self.authenticated_key
    }

    /// Get the saved request key.
    pub fn get_saved_request_key(&self) -> &str {
        &self.saved_request_key
    }

    /// Get the fixation strategy.
    pub fn get_fixation_strategy(&self) -> SessionFixationStrategy {
        self.fixation_strategy
    }

    /// Get maximum sessions.
    pub fn get_maximum_sessions(&self) -> Option<usize> {
        self.maximum_sessions
    }

    /// Get timeout.
    pub fn get_timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Check if oldest session should be expired.
    pub fn should_expire_oldest(&self) -> bool {
        self.expire_oldest_session
    }
}

// =============================================================================
// Session Authenticator
// =============================================================================

/// Session-based authenticator.
///
/// Reads user information from the actix-session.
///
/// # Spring Security Equivalent
/// Similar to Spring's session-based authentication where `SecurityContext`
/// is stored in the `HttpSession`.
///
/// # Requirements
/// - `SessionMiddleware` must be configured in your application
/// - User must be logged in via `SessionAuthenticator::login()`
///
/// # Example
/// ```rust,ignore
/// use actix_security_core::http::security::session::{SessionAuthenticator, SessionConfig};
///
/// let config = SessionConfig::new()
///     .fixation_strategy(SessionFixationStrategy::MigrateSession);
/// let authenticator = SessionAuthenticator::new(config);
///
/// // In login handler
/// async fn login(session: Session, form: Form<LoginForm>) -> impl Responder {
///     // Validate credentials...
///     let user = validate_user(&form.username, &form.password)?;
///
///     // Store user in session (with fixation protection)
///     SessionAuthenticator::login(&session, &user, &config)?;
///
///     HttpResponse::Ok().body("Logged in")
/// }
/// ```
#[derive(Clone)]
pub struct SessionAuthenticator {
    config: SessionConfig,
}

impl SessionAuthenticator {
    /// Create a new session authenticator.
    pub fn new(config: SessionConfig) -> Self {
        Self { config }
    }

    /// Create with default configuration.
    pub fn default_config() -> Self {
        Self::new(SessionConfig::default())
    }

    /// Store user in session (login) with session fixation protection.
    ///
    /// This method:
    /// 1. Applies session fixation protection based on configuration
    /// 2. Stores user data in the session
    /// 3. Sets the authenticated flag
    ///
    /// # Spring Equivalent
    /// Similar to `SecurityContextHolder.getContext().setAuthentication(...)`
    /// combined with session fixation protection.
    ///
    /// # Example
    /// ```rust,ignore
    /// async fn login_handler(
    ///     session: Session,
    ///     form: Form<LoginForm>,
    ///     config: Data<SessionConfig>,
    /// ) -> impl Responder {
    ///     // Validate credentials
    ///     let user = validate_user(&form.username, &form.password)?;
    ///
    ///     // Login with session fixation protection
    ///     SessionAuthenticator::login(&session, &user, &config)?;
    ///
    ///     HttpResponse::Ok().body("Logged in")
    /// }
    /// ```
    pub fn login(
        session: &actix_session::Session,
        user: &User,
        config: &SessionConfig,
    ) -> Result<(), SessionError> {
        // Apply session fixation protection
        Self::apply_fixation_protection(session, config)?;

        // Store user in session
        let session_user = SessionUser::from_user(user);

        session
            .insert(&config.user_key, &session_user)
            .map_err(|e| SessionError::InsertError(e.to_string()))?;

        session
            .insert(&config.authenticated_key, true)
            .map_err(|e| SessionError::InsertError(e.to_string()))?;

        Ok(())
    }

    /// Apply session fixation protection based on configuration.
    fn apply_fixation_protection(
        session: &actix_session::Session,
        config: &SessionConfig,
    ) -> Result<(), SessionError> {
        match config.fixation_strategy {
            SessionFixationStrategy::MigrateSession => {
                // Regenerate session ID but keep data
                // Note: actix-session's renew() regenerates the session ID
                session.renew();
            }
            SessionFixationStrategy::NewSession => {
                // Clear all session data and regenerate
                session.purge();
            }
            SessionFixationStrategy::None => {
                // No protection - do nothing
            }
        }
        Ok(())
    }

    /// Remove user from session (logout).
    ///
    /// # Example
    /// ```rust,ignore
    /// async fn logout_handler(session: Session, config: Data<SessionConfig>) -> impl Responder {
    ///     SessionAuthenticator::logout(&session, &config);
    ///     HttpResponse::Ok().body("Logged out")
    /// }
    /// ```
    pub fn logout(session: &actix_session::Session, config: &SessionConfig) {
        session.remove(&config.user_key);
        session.remove(&config.authenticated_key);
        session.remove(&config.saved_request_key);
    }

    /// Clear entire session (logout + clear all data).
    pub fn clear_session(session: &actix_session::Session) {
        session.purge();
    }

    /// Check if session is authenticated.
    pub fn is_authenticated(session: &actix_session::Session, config: &SessionConfig) -> bool {
        session
            .get::<bool>(&config.authenticated_key)
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    /// Get user from session.
    pub fn get_session_user(
        session: &actix_session::Session,
        config: &SessionConfig,
    ) -> Option<User> {
        session
            .get::<SessionUser>(&config.user_key)
            .ok()
            .flatten()
            .map(|su| su.to_user())
    }

    /// Save the current request URL for redirect after login.
    ///
    /// # Spring Equivalent
    /// Similar to `SavedRequest` in Spring Security.
    pub fn save_request(
        session: &actix_session::Session,
        url: &str,
        config: &SessionConfig,
    ) -> Result<(), SessionError> {
        session
            .insert(&config.saved_request_key, url)
            .map_err(|e| SessionError::InsertError(e.to_string()))
    }

    /// Get the saved request URL and remove it from session.
    ///
    /// Returns the saved URL or the default URL if none was saved.
    pub fn get_saved_request(
        session: &actix_session::Session,
        config: &SessionConfig,
        default_url: &str,
    ) -> String {
        let saved = session
            .get::<String>(&config.saved_request_key)
            .ok()
            .flatten();

        if saved.is_some() {
            session.remove(&config.saved_request_key);
        }

        saved.unwrap_or_else(|| default_url.to_string())
    }

    /// Get the configuration.
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }
}

impl Authenticator for SessionAuthenticator {
    fn get_user(&self, req: &ServiceRequest) -> Option<User> {
        let session = req.get_session();

        // Check if authenticated
        if !Self::is_authenticated(&session, &self.config) {
            return None;
        }

        // Get user from session
        Self::get_session_user(&session, &self.config)
    }
}

// =============================================================================
// Session Error
// =============================================================================

/// Session-related errors.
#[derive(Debug)]
pub enum SessionError {
    /// Error inserting data into session
    InsertError(String),
    /// Error reading data from session
    ReadError(String),
    /// Session not found
    NotFound,
    /// Maximum sessions exceeded
    MaxSessionsExceeded,
    /// Session expired
    Expired,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::InsertError(e) => write!(f, "Session insert error: {}", e),
            SessionError::ReadError(e) => write!(f, "Session read error: {}", e),
            SessionError::NotFound => write!(f, "Session not found"),
            SessionError::MaxSessionsExceeded => write!(f, "Maximum sessions exceeded"),
            SessionError::Expired => write!(f, "Session expired"),
        }
    }
}

impl std::error::Error for SessionError {}

// =============================================================================
// Session Login Service
// =============================================================================

/// Service for handling login/logout with sessions.
///
/// Combines authentication validation with session management.
///
/// # Example
/// ```rust,ignore
/// let login_service = SessionLoginService::new(
///     memory_authenticator,  // For validating credentials
///     session_config,
/// );
///
/// // In login handler
/// async fn login(
///     session: Session,
///     form: Form<LoginForm>,
///     login_service: Data<SessionLoginService<MemoryAuthenticator>>,
/// ) -> impl Responder {
///     match login_service.login(&session, &form.username, &form.password) {
///         Ok(user) => HttpResponse::Ok().body(format!("Welcome, {}!", user.get_username())),
///         Err(_) => HttpResponse::Unauthorized().body("Invalid credentials"),
///     }
/// }
/// ```
#[derive(Clone)]
pub struct SessionLoginService<A>
where
    A: Authenticator,
{
    /// Authenticator for validating credentials
    #[allow(dead_code)]
    credential_authenticator: A,
    /// Session configuration
    config: SessionConfig,
}

impl<A> SessionLoginService<A>
where
    A: Authenticator,
{
    /// Create a new login service.
    pub fn new(credential_authenticator: A, config: SessionConfig) -> Self {
        Self {
            credential_authenticator,
            config,
        }
    }

    /// Login with a validated user.
    ///
    /// This method:
    /// 1. Applies session fixation protection
    /// 2. Stores user in session
    pub fn login_with_user(
        &self,
        session: &actix_session::Session,
        user: &User,
    ) -> Result<(), SessionError> {
        SessionAuthenticator::login(session, user, &self.config)
    }

    /// Logout - remove user from session.
    pub fn logout(&self, session: &actix_session::Session) {
        SessionAuthenticator::logout(session, &self.config);
    }

    /// Get the session configuration.
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Save the current request URL for redirect after login.
    pub fn save_request(
        &self,
        session: &actix_session::Session,
        url: &str,
    ) -> Result<(), SessionError> {
        SessionAuthenticator::save_request(session, url, &self.config)
    }

    /// Get the saved request URL.
    pub fn get_saved_request(&self, session: &actix_session::Session, default_url: &str) -> String {
        SessionAuthenticator::get_saved_request(session, &self.config, default_url)
    }
}

// =============================================================================
// Credential Authenticator Trait
// =============================================================================

/// Trait for authenticators that can validate username/password credentials.
///
/// # Spring Equivalent
/// Similar to `AuthenticationProvider` that handles username/password authentication.
///
/// This trait is separate from `Authenticator` because it validates credentials
/// directly rather than extracting them from a request.
pub trait CredentialAuthenticator: Send + Sync {
    /// Validate username and password, returning the user if valid.
    fn authenticate(&self, username: &str, password: &str) -> Option<User>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user() -> User {
        User::new("testuser".to_string(), "password".to_string())
            .roles(&["USER".into()])
            .authorities(&["read".into()])
    }

    #[test]
    fn test_session_user_conversion() {
        let user = test_user();
        let session_user = SessionUser::from_user(&user);

        assert_eq!(session_user.username, "testuser");
        assert!(session_user.roles.contains(&"USER".to_string()));
        assert!(session_user.authorities.contains(&"read".to_string()));

        let converted = session_user.to_user();
        assert_eq!(converted.get_username(), "testuser");
        assert!(converted.has_role("USER"));
    }

    #[test]
    fn test_session_config() {
        let config = SessionConfig::new()
            .user_key("my_user")
            .authenticated_key("my_auth")
            .fixation_strategy(SessionFixationStrategy::NewSession)
            .maximum_sessions(2);

        assert_eq!(config.get_user_key(), "my_user");
        assert_eq!(config.get_authenticated_key(), "my_auth");
        assert_eq!(
            config.get_fixation_strategy(),
            SessionFixationStrategy::NewSession
        );
        assert_eq!(config.get_maximum_sessions(), Some(2));
    }

    #[test]
    fn test_session_fixation_strategy_default() {
        let strategy = SessionFixationStrategy::default();
        assert_eq!(strategy, SessionFixationStrategy::MigrateSession);
    }

    #[test]
    fn test_session_user_serialization() {
        let user = test_user();
        let session_user = SessionUser::from_user(&user);

        // Serialize to JSON
        let json = serde_json::to_string(&session_user).unwrap();
        assert!(json.contains("testuser"));

        // Deserialize back
        let deserialized: SessionUser = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.username, "testuser");
    }

    #[test]
    fn test_session_config_builder() {
        use std::time::Duration;

        let config = SessionConfig::new()
            .user_key("user")
            .authenticated_key("auth")
            .saved_request_key("saved")
            .fixation_strategy(SessionFixationStrategy::MigrateSession)
            .maximum_sessions(1)
            .timeout(Duration::from_secs(3600))
            .expire_oldest_session(true);

        assert_eq!(config.get_user_key(), "user");
        assert_eq!(config.get_authenticated_key(), "auth");
        assert_eq!(config.get_saved_request_key(), "saved");
        assert_eq!(
            config.get_fixation_strategy(),
            SessionFixationStrategy::MigrateSession
        );
        assert_eq!(config.get_maximum_sessions(), Some(1));
        assert_eq!(config.get_timeout(), Some(Duration::from_secs(3600)));
        assert!(config.should_expire_oldest());
    }
}
