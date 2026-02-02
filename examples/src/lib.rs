//! Common utilities for actix-security examples and tests.
//!
//! This module provides shared test infrastructure that can be used
//! by both examples and integration tests.

use actix_security::http::security::{Argon2PasswordEncoder, PasswordEncoder, User};

/// Common test users for all examples.
pub struct TestUsers {
    pub admin: User,
    pub user: User,
    pub guest: User,
    pub encoder: Argon2PasswordEncoder,
}

impl TestUsers {
    /// Create standard test users with Argon2-encoded passwords.
    pub fn new() -> Self {
        let encoder = Argon2PasswordEncoder::new();

        Self {
            admin: User::with_encoded_password("admin", encoder.encode("admin"))
                .roles(&["ADMIN".into(), "USER".into()])
                .authorities(&["users:read".into(), "users:write".into()]),
            user: User::with_encoded_password("user", encoder.encode("user"))
                .roles(&["USER".into()])
                .authorities(&["users:read".into()]),
            guest: User::with_encoded_password("guest", encoder.encode("guest"))
                .roles(&["GUEST".into()]),
            encoder,
        }
    }

    /// Get all users as a vector.
    pub fn all(&self) -> Vec<User> {
        vec![self.admin.clone(), self.user.clone(), self.guest.clone()]
    }

    /// Get admin and user only (no guest).
    pub fn authenticated(&self) -> Vec<User> {
        vec![self.admin.clone(), self.user.clone()]
    }
}

impl Default for TestUsers {
    fn default() -> Self {
        Self::new()
    }
}

/// Test credentials for HTTP requests.
pub mod credentials {
    use base64::prelude::*;

    /// Create HTTP Basic auth header value.
    pub fn basic_auth(username: &str, password: &str) -> String {
        let credentials = format!("{}:{}", username, password);
        format!("Basic {}", BASE64_STANDARD.encode(credentials))
    }

    /// Admin credentials (admin:admin).
    pub fn admin() -> (&'static str, &'static str) {
        ("admin", "admin")
    }

    /// User credentials (user:user).
    pub fn user() -> (&'static str, &'static str) {
        ("user", "user")
    }

    /// Guest credentials (guest:guest).
    pub fn guest() -> (&'static str, &'static str) {
        ("guest", "guest")
    }
}

/// Test server utilities.
pub mod server {
    use actix_web::body::MessageBody;
    use actix_web::dev::ServiceResponse;
    use actix_web::http::StatusCode;

    /// Assert response status code.
    pub fn assert_status<B: MessageBody>(response: &ServiceResponse<B>, expected: StatusCode) {
        assert_eq!(
            response.status(),
            expected,
            "Expected status {}, got {}",
            expected,
            response.status()
        );
    }

    /// Assert response is OK (200).
    pub fn assert_ok<B: MessageBody>(response: &ServiceResponse<B>) {
        assert_status(response, StatusCode::OK);
    }

    /// Assert response is Unauthorized (401).
    pub fn assert_unauthorized<B: MessageBody>(response: &ServiceResponse<B>) {
        assert_status(response, StatusCode::UNAUTHORIZED);
    }

    /// Assert response is Forbidden (403).
    pub fn assert_forbidden<B: MessageBody>(response: &ServiceResponse<B>) {
        assert_status(response, StatusCode::FORBIDDEN);
    }

    /// Assert response is a redirect (302).
    pub fn assert_redirect<B: MessageBody>(response: &ServiceResponse<B>) {
        assert_status(response, StatusCode::FOUND);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_users_creation() {
        let users = TestUsers::new();
        assert_eq!(users.admin.get_username(), "admin");
        assert_eq!(users.user.get_username(), "user");
        assert_eq!(users.guest.get_username(), "guest");
    }

    #[test]
    fn test_credentials_basic_auth() {
        let auth = credentials::basic_auth("admin", "admin");
        assert!(auth.starts_with("Basic "));
    }
}
