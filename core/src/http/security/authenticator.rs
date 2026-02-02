//! In-Memory User Details Manager.
//!
//! # Spring Security Equivalent
//! `org.springframework.security.provisioning.InMemoryUserDetailsManager`

use std::collections::HashMap;
use std::sync::Arc;

use actix_web::dev::ServiceRequest;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

use crate::http::security::config::Authenticator;
use crate::http::security::crypto::{NoOpPasswordEncoder, PasswordEncoder};
use crate::http::security::user::User;

#[cfg(feature = "http-basic")]
use crate::http::security::http_basic::extract_basic_auth;

/// In-memory user store for authentication.
///
/// # Spring Security Equivalent
/// `InMemoryUserDetailsManager`
///
/// # Example
/// ```ignore
/// use actix_security_core::http::security::{AuthenticationManager, User};
/// use actix_security_core::http::security::crypto::Argon2PasswordEncoder;
///
/// let encoder = Argon2PasswordEncoder::new();
/// let authenticator = AuthenticationManager::in_memory_authentication()
///     .password_encoder(encoder.clone())
///     .with_user(
///         User::with_encoded_password("admin", encoder.encode("secret"))
///             .roles(&["ADMIN".into()])
///     );
/// ```
pub struct MemoryAuthenticator {
    users: HashMap<String, User>,
    logged_users: HashMap<String, String>,
    password_encoder: Arc<dyn PasswordEncoder>,
}

impl MemoryAuthenticator {
    /// Creates a new in-memory authenticator with no users.
    pub fn new() -> Self {
        MemoryAuthenticator {
            users: HashMap::new(),
            logged_users: HashMap::new(),
            password_encoder: Arc::new(NoOpPasswordEncoder),
        }
    }

    /// Sets the password encoder for verifying passwords.
    ///
    /// # Spring Security Equivalent
    /// `AuthenticationManagerBuilder.passwordEncoder(PasswordEncoder)`
    ///
    /// # Example
    /// ```ignore
    /// let encoder = Argon2PasswordEncoder::new();
    /// let authenticator = MemoryAuthenticator::new()
    ///     .password_encoder(encoder);
    /// ```
    pub fn password_encoder<E: PasswordEncoder + 'static>(mut self, encoder: E) -> Self {
        self.password_encoder = Arc::new(encoder);
        self
    }

    /// Adds a user to the in-memory store.
    ///
    /// # Example
    /// ```ignore
    /// let authenticator = MemoryAuthenticator::new()
    ///     .with_user(User::new("admin".into(), "password".into()));
    /// ```
    pub fn with_user(mut self, user: User) -> Self {
        use std::collections::hash_map::Entry;
        let user_name = user.get_username().to_string();
        match self.users.entry(user_name) {
            Entry::Occupied(e) => {
                eprintln!("Warning: User {} already exists, skipping", e.key());
            }
            Entry::Vacant(e) => {
                e.insert(user);
            }
        }
        self
    }

    /// Logs in a user and returns a session ID.
    ///
    /// Returns `None` if credentials are invalid.
    pub fn login(&mut self, user_name: String, password: String) -> Option<String> {
        self.users.get(&user_name).and_then(|u| {
            if self.password_encoder.matches(&password, u.get_password()) {
                let id: String = thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(30)
                    .map(char::from)
                    .collect();
                self.logged_users.insert(id.clone(), user_name);
                Some(id)
            } else {
                None
            }
        })
    }

    /// Logs out a user by session ID.
    pub fn logout(&mut self, id: &str) {
        self.logged_users.remove(id);
    }

    /// Verifies credentials and returns the user if valid.
    pub(crate) fn verify_credentials(&self, username: &str, password: &str) -> Option<User> {
        self.users.get(username).and_then(|user| {
            if self.password_encoder.matches(password, user.get_password()) {
                Some(user.clone())
            } else {
                None
            }
        })
    }
}

impl Default for MemoryAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MemoryAuthenticator {
    fn clone(&self) -> Self {
        MemoryAuthenticator {
            logged_users: self
                .logged_users
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            users: self
                .users
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            password_encoder: Arc::clone(&self.password_encoder),
        }
    }
}

impl Authenticator for MemoryAuthenticator {
    fn get_user(&self, req: &ServiceRequest) -> Option<User> {
        // Try HTTP Basic Auth first (if feature enabled)
        #[cfg(feature = "http-basic")]
        if let Some(user) = extract_basic_auth(req, |username, password| {
            self.verify_credentials(username, password)
        }) {
            return Some(user);
        }

        // Fall back to header-based auth (for backward compatibility)
        let user_name = req.headers().get("user_name")?.to_str().ok()?;
        let password = req.headers().get("password")?.to_str().ok()?;
        self.verify_credentials(user_name, password)
    }
}
