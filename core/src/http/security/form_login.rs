//! Form-based Login Authentication.
//!
//! # Spring Security Equivalent
//! Similar to Spring Security's `formLogin()` configuration.
//!
//! # Features
//! - POST-based login form processing
//! - Configurable login/logout URLs
//! - Saved request redirect after login
//! - Session fixation protection
//! - CSRF integration
//! - Remember-me support
//!
//! # Example
//! ```rust,ignore
//! use actix_security_core::http::security::form_login::{FormLoginConfig, FormLoginHandler};
//!
//! let form_login = FormLoginConfig::new()
//!     .login_page("/login")
//!     .login_processing_url("/login")
//!     .default_success_url("/dashboard")
//!     .failure_url("/login?error=true")
//!     .logout_url("/logout")
//!     .logout_success_url("/login?logout");
//!
//! // The form login handler processes POST /login
//! // and redirects on success/failure
//! ```

use crate::http::security::session::{
    CredentialAuthenticator, SessionAuthenticator, SessionConfig,
};
use crate::http::security::User;
use actix_web::http::header::LOCATION;
use actix_web::HttpResponse;
use serde::Deserialize;

// =============================================================================
// Form Login Configuration
// =============================================================================

/// Form login configuration.
///
/// # Spring Security Equivalent
/// Similar to `FormLoginConfigurer` in Spring Security.
///
/// # Example
/// ```rust,ignore
/// let config = FormLoginConfig::new()
///     .login_page("/login")
///     .login_processing_url("/login")
///     .username_parameter("username")
///     .password_parameter("password")
///     .default_success_url("/")
///     .failure_url("/login?error");
/// ```
#[derive(Clone)]
pub struct FormLoginConfig {
    /// URL of the login page (GET)
    login_page: String,
    /// URL that processes login form (POST)
    login_processing_url: String,
    /// Form parameter name for username
    username_parameter: String,
    /// Form parameter name for password
    password_parameter: String,
    /// Default URL after successful login
    default_success_url: String,
    /// Always redirect to default success URL (ignore saved request)
    always_use_default_success_url: bool,
    /// URL after failed login
    failure_url: String,
    /// URL for logout (POST)
    logout_url: String,
    /// URL after successful logout
    logout_success_url: String,
    /// Form parameter name for remember-me checkbox
    remember_me_parameter: Option<String>,
}

impl Default for FormLoginConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl FormLoginConfig {
    /// Create a new form login configuration with default values.
    pub fn new() -> Self {
        Self {
            login_page: "/login".to_string(),
            login_processing_url: "/login".to_string(),
            username_parameter: "username".to_string(),
            password_parameter: "password".to_string(),
            default_success_url: "/".to_string(),
            always_use_default_success_url: false,
            failure_url: "/login?error".to_string(),
            logout_url: "/logout".to_string(),
            logout_success_url: "/login?logout".to_string(),
            remember_me_parameter: None,
        }
    }

    /// Set the login page URL (GET request).
    ///
    /// # Spring Equivalent
    /// `formLogin().loginPage("/login")`
    pub fn login_page(mut self, url: &str) -> Self {
        self.login_page = url.to_string();
        self
    }

    /// Set the login processing URL (POST request).
    ///
    /// # Spring Equivalent
    /// `formLogin().loginProcessingUrl("/login")`
    pub fn login_processing_url(mut self, url: &str) -> Self {
        self.login_processing_url = url.to_string();
        self
    }

    /// Set the username parameter name.
    ///
    /// # Spring Equivalent
    /// `formLogin().usernameParameter("username")`
    pub fn username_parameter(mut self, param: &str) -> Self {
        self.username_parameter = param.to_string();
        self
    }

    /// Set the password parameter name.
    ///
    /// # Spring Equivalent
    /// `formLogin().passwordParameter("password")`
    pub fn password_parameter(mut self, param: &str) -> Self {
        self.password_parameter = param.to_string();
        self
    }

    /// Set the default success URL.
    ///
    /// # Spring Equivalent
    /// `formLogin().defaultSuccessUrl("/")`
    pub fn default_success_url(mut self, url: &str) -> Self {
        self.default_success_url = url.to_string();
        self
    }

    /// Always redirect to default success URL, ignoring saved request.
    ///
    /// # Spring Equivalent
    /// `formLogin().defaultSuccessUrl("/", true)`
    pub fn always_use_default_success_url(mut self, always: bool) -> Self {
        self.always_use_default_success_url = always;
        self
    }

    /// Set the failure URL.
    ///
    /// # Spring Equivalent
    /// `formLogin().failureUrl("/login?error")`
    pub fn failure_url(mut self, url: &str) -> Self {
        self.failure_url = url.to_string();
        self
    }

    /// Set the logout URL (POST request).
    ///
    /// # Spring Equivalent
    /// `logout().logoutUrl("/logout")`
    pub fn logout_url(mut self, url: &str) -> Self {
        self.logout_url = url.to_string();
        self
    }

    /// Set the logout success URL.
    ///
    /// # Spring Equivalent
    /// `logout().logoutSuccessUrl("/login?logout")`
    pub fn logout_success_url(mut self, url: &str) -> Self {
        self.logout_success_url = url.to_string();
        self
    }

    /// Enable remember-me with the given parameter name.
    pub fn remember_me_parameter(mut self, param: &str) -> Self {
        self.remember_me_parameter = Some(param.to_string());
        self
    }

    // Getters

    /// Get the login page URL.
    pub fn get_login_page(&self) -> &str {
        &self.login_page
    }

    /// Get the login processing URL.
    pub fn get_login_processing_url(&self) -> &str {
        &self.login_processing_url
    }

    /// Get the username parameter name.
    pub fn get_username_parameter(&self) -> &str {
        &self.username_parameter
    }

    /// Get the password parameter name.
    pub fn get_password_parameter(&self) -> &str {
        &self.password_parameter
    }

    /// Get the default success URL.
    pub fn get_default_success_url(&self) -> &str {
        &self.default_success_url
    }

    /// Check if always use default success URL.
    pub fn is_always_use_default_success_url(&self) -> bool {
        self.always_use_default_success_url
    }

    /// Get the failure URL.
    pub fn get_failure_url(&self) -> &str {
        &self.failure_url
    }

    /// Get the logout URL.
    pub fn get_logout_url(&self) -> &str {
        &self.logout_url
    }

    /// Get the logout success URL.
    pub fn get_logout_success_url(&self) -> &str {
        &self.logout_success_url
    }

    /// Get the remember-me parameter name.
    pub fn get_remember_me_parameter(&self) -> Option<&str> {
        self.remember_me_parameter.as_deref()
    }
}

// =============================================================================
// Login Form Data
// =============================================================================

/// Login form data structure.
///
/// This is the expected form data for login requests.
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    /// Username from form
    pub username: String,
    /// Password from form
    pub password: String,
    /// Remember-me checkbox (optional)
    #[serde(default)]
    pub remember_me: Option<String>,
}

impl LoginForm {
    /// Check if remember-me is enabled.
    pub fn is_remember_me(&self) -> bool {
        self.remember_me
            .as_ref()
            .map(|v| v == "on" || v == "true" || v == "1")
            .unwrap_or(false)
    }
}

// =============================================================================
// Form Login Handler
// =============================================================================

/// Form login handler for processing login/logout requests.
///
/// # Spring Security Equivalent
/// Similar to `UsernamePasswordAuthenticationFilter` in Spring Security.
///
/// # Example
/// ```rust,ignore
/// use actix_security_core::http::security::form_login::{FormLoginHandler, FormLoginConfig, LoginForm};
/// use actix_security_core::http::security::session::SessionConfig;
///
/// let handler = FormLoginHandler::new(
///     FormLoginConfig::new(),
///     SessionConfig::new(),
/// );
///
/// // In your login route handler
/// async fn login(
///     session: Session,
///     form: Form<LoginForm>,
///     authenticator: Data<MemoryAuthenticator>,
///     handler: Data<FormLoginHandler>,
/// ) -> impl Responder {
///     // Validate credentials
///     if let Some(user) = authenticator.verify_credentials(&form.username, &form.password) {
///         handler.on_authentication_success(&session, &user, None)
///     } else {
///         handler.on_authentication_failure()
///     }
/// }
/// ```
#[derive(Clone)]
pub struct FormLoginHandler {
    config: FormLoginConfig,
    session_config: SessionConfig,
}

impl FormLoginHandler {
    /// Create a new form login handler.
    pub fn new(config: FormLoginConfig, session_config: SessionConfig) -> Self {
        Self {
            config,
            session_config,
        }
    }

    /// Handle successful authentication.
    ///
    /// This method:
    /// 1. Stores user in session
    /// 2. Redirects to saved request URL or default success URL
    ///
    /// # Arguments
    /// * `session` - The actix session
    /// * `user` - The authenticated user
    /// * `saved_url` - Optional saved URL from before login redirect
    pub fn on_authentication_success(
        &self,
        session: &actix_session::Session,
        user: &User,
        saved_url: Option<String>,
    ) -> HttpResponse {
        // Store user in session with fixation protection
        if SessionAuthenticator::login(session, user, &self.session_config).is_err() {
            return self.on_authentication_failure();
        }

        // Determine redirect URL
        let redirect_url = if self.config.always_use_default_success_url {
            self.config.default_success_url.clone()
        } else {
            saved_url.unwrap_or_else(|| {
                SessionAuthenticator::get_saved_request(
                    session,
                    &self.session_config,
                    &self.config.default_success_url,
                )
            })
        };

        HttpResponse::Found()
            .insert_header((LOCATION, redirect_url))
            .finish()
    }

    /// Handle failed authentication.
    ///
    /// Redirects to the failure URL.
    pub fn on_authentication_failure(&self) -> HttpResponse {
        HttpResponse::Found()
            .insert_header((LOCATION, self.config.failure_url.clone()))
            .finish()
    }

    /// Handle logout.
    ///
    /// This method:
    /// 1. Removes user from session
    /// 2. Redirects to logout success URL
    pub fn on_logout(&self, session: &actix_session::Session) -> HttpResponse {
        SessionAuthenticator::logout(session, &self.session_config);

        HttpResponse::Found()
            .insert_header((LOCATION, self.config.logout_success_url.clone()))
            .finish()
    }

    /// Save the current request URL for redirect after login.
    ///
    /// Call this before redirecting to the login page.
    pub fn save_request(&self, session: &actix_session::Session, url: &str) {
        let _ = SessionAuthenticator::save_request(session, url, &self.session_config);
    }

    /// Get the login page URL.
    pub fn login_page_url(&self) -> &str {
        &self.config.login_page
    }

    /// Get the login processing URL.
    pub fn login_processing_url(&self) -> &str {
        &self.config.login_processing_url
    }

    /// Get the logout URL.
    pub fn logout_url(&self) -> &str {
        &self.config.logout_url
    }

    /// Check if a URL is the login page.
    pub fn is_login_page(&self, url: &str) -> bool {
        url == self.config.login_page || url.starts_with(&format!("{}?", self.config.login_page))
    }

    /// Check if a URL is the login processing URL.
    pub fn is_login_processing_url(&self, url: &str) -> bool {
        url == self.config.login_processing_url
    }

    /// Check if a URL is the logout URL.
    pub fn is_logout_url(&self, url: &str) -> bool {
        url == self.config.logout_url
    }

    /// Get the form login configuration.
    pub fn config(&self) -> &FormLoginConfig {
        &self.config
    }

    /// Get the session configuration.
    pub fn session_config(&self) -> &SessionConfig {
        &self.session_config
    }
}

// =============================================================================
// Form Login Service
// =============================================================================

/// Complete form login service combining authentication and session management.
///
/// # Example
/// ```rust,ignore
/// let service = FormLoginService::new(
///     memory_authenticator,
///     FormLoginConfig::new(),
///     SessionConfig::new(),
/// );
///
/// // In login handler
/// async fn login(
///     session: Session,
///     form: Form<LoginForm>,
///     service: Data<FormLoginService<MemoryAuthenticator>>,
/// ) -> impl Responder {
///     service.attempt_authentication(&session, &form.username, &form.password)
/// }
/// ```
#[derive(Clone)]
pub struct FormLoginService<A>
where
    A: CredentialAuthenticator + Clone,
{
    authenticator: A,
    handler: FormLoginHandler,
}

impl<A> FormLoginService<A>
where
    A: CredentialAuthenticator + Clone,
{
    /// Create a new form login service.
    pub fn new(authenticator: A, config: FormLoginConfig, session_config: SessionConfig) -> Self {
        Self {
            authenticator,
            handler: FormLoginHandler::new(config, session_config),
        }
    }

    /// Attempt authentication with username and password.
    ///
    /// Returns an HTTP response (redirect to success or failure URL).
    pub fn attempt_authentication(
        &self,
        session: &actix_session::Session,
        username: &str,
        password: &str,
    ) -> HttpResponse {
        match self.authenticator.authenticate(username, password) {
            Some(user) => self.handler.on_authentication_success(session, &user, None),
            None => self.handler.on_authentication_failure(),
        }
    }

    /// Attempt authentication with login form data.
    pub fn attempt_authentication_with_form(
        &self,
        session: &actix_session::Session,
        form: &LoginForm,
    ) -> HttpResponse {
        self.attempt_authentication(session, &form.username, &form.password)
    }

    /// Handle logout.
    pub fn logout(&self, session: &actix_session::Session) -> HttpResponse {
        self.handler.on_logout(session)
    }

    /// Get the form login handler.
    pub fn handler(&self) -> &FormLoginHandler {
        &self.handler
    }

    /// Get the authenticator.
    pub fn authenticator(&self) -> &A {
        &self.authenticator
    }
}

// =============================================================================
// Form Login Error
// =============================================================================

/// Form login related errors.
#[derive(Debug)]
pub enum FormLoginError {
    /// Invalid credentials
    InvalidCredentials,
    /// Session error
    SessionError(String),
    /// Missing required parameter
    MissingParameter(String),
}

impl std::fmt::Display for FormLoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormLoginError::InvalidCredentials => write!(f, "Invalid credentials"),
            FormLoginError::SessionError(e) => write!(f, "Session error: {}", e),
            FormLoginError::MissingParameter(p) => write!(f, "Missing parameter: {}", p),
        }
    }
}

impl std::error::Error for FormLoginError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_form_login_config_default() {
        let config = FormLoginConfig::new();

        assert_eq!(config.get_login_page(), "/login");
        assert_eq!(config.get_login_processing_url(), "/login");
        assert_eq!(config.get_username_parameter(), "username");
        assert_eq!(config.get_password_parameter(), "password");
        assert_eq!(config.get_default_success_url(), "/");
        assert_eq!(config.get_failure_url(), "/login?error");
        assert_eq!(config.get_logout_url(), "/logout");
        assert_eq!(config.get_logout_success_url(), "/login?logout");
    }

    #[test]
    fn test_form_login_config_builder() {
        let config = FormLoginConfig::new()
            .login_page("/auth/login")
            .login_processing_url("/auth/authenticate")
            .username_parameter("user")
            .password_parameter("pass")
            .default_success_url("/dashboard")
            .failure_url("/auth/login?failed=true")
            .logout_url("/auth/logout")
            .logout_success_url("/auth/login?loggedout")
            .remember_me_parameter("rememberMe")
            .always_use_default_success_url(true);

        assert_eq!(config.get_login_page(), "/auth/login");
        assert_eq!(config.get_login_processing_url(), "/auth/authenticate");
        assert_eq!(config.get_username_parameter(), "user");
        assert_eq!(config.get_password_parameter(), "pass");
        assert_eq!(config.get_default_success_url(), "/dashboard");
        assert!(config.is_always_use_default_success_url());
        assert_eq!(config.get_failure_url(), "/auth/login?failed=true");
        assert_eq!(config.get_logout_url(), "/auth/logout");
        assert_eq!(config.get_logout_success_url(), "/auth/login?loggedout");
        assert_eq!(config.get_remember_me_parameter(), Some("rememberMe"));
    }

    #[test]
    fn test_login_form_remember_me() {
        let form = LoginForm {
            username: "user".to_string(),
            password: "pass".to_string(),
            remember_me: Some("on".to_string()),
        };
        assert!(form.is_remember_me());

        let form2 = LoginForm {
            username: "user".to_string(),
            password: "pass".to_string(),
            remember_me: Some("true".to_string()),
        };
        assert!(form2.is_remember_me());

        let form3 = LoginForm {
            username: "user".to_string(),
            password: "pass".to_string(),
            remember_me: None,
        };
        assert!(!form3.is_remember_me());
    }

    #[test]
    fn test_form_login_handler_url_checks() {
        let config = FormLoginConfig::new()
            .login_page("/login")
            .logout_url("/logout");

        let handler = FormLoginHandler::new(config, SessionConfig::new());

        assert!(handler.is_login_page("/login"));
        assert!(handler.is_login_page("/login?error"));
        assert!(!handler.is_login_page("/dashboard"));

        assert!(handler.is_logout_url("/logout"));
        assert!(!handler.is_logout_url("/login"));
    }
}
