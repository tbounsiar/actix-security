//! User model for authentication and authorization.
//!
//! # Spring Equivalent
//! `UserDetails` interface

use std::fmt;

/// Represents an authenticated user with roles and authorities.
///
/// # Spring Equivalent
/// `UserDetails` / `User`
///
/// # Example
/// ```
/// use actix_security_core::http::security::User;
///
/// let user = User::new("admin".into(), "password".into())
///     .roles(&["ADMIN".into(), "USER".into()])
///     .authorities(&["users:read".into(), "users:write".into()]);
///
/// assert!(user.has_role("ADMIN"));
/// assert!(user.has_authority("users:read"));
/// ```
#[derive(Clone, Debug)]
pub struct User {
    username: String,
    password: String,
    roles: Vec<String>,
    authorities: Vec<String>,
}

impl User {
    /// Creates a new user with username and plain-text password.
    ///
    /// # Note
    /// For production use, prefer `with_encoded_password` with a proper
    /// password encoder like Argon2.
    pub fn new(username: String, password: String) -> Self {
        User {
            username,
            password,
            roles: Vec::new(),
            authorities: Vec::new(),
        }
    }

    /// Creates a new user with username and pre-encoded password.
    ///
    /// # Spring Security Equivalent
    /// `User.withUsername().password("{bcrypt}$2a$...").build()`
    ///
    /// # Example
    /// ```
    /// use actix_security_core::http::security::{User, Argon2PasswordEncoder, PasswordEncoder};
    ///
    /// let encoder = Argon2PasswordEncoder::new();
    /// let encoded = encoder.encode("secret");
    ///
    /// let user = User::with_encoded_password("admin", encoded)
    ///     .roles(&["ADMIN".into()]);
    /// ```
    pub fn with_encoded_password(username: &str, encoded_password: String) -> Self {
        User {
            username: username.to_string(),
            password: encoded_password,
            roles: Vec::new(),
            authorities: Vec::new(),
        }
    }

    /// Returns the username.
    pub fn get_username(&self) -> &str {
        &self.username
    }

    /// Returns the password (for authentication checks).
    pub fn get_password(&self) -> &str {
        &self.password
    }

    /// Returns the user's roles.
    pub fn get_roles(&self) -> &[String] {
        &self.roles
    }

    /// Returns the user's authorities.
    pub fn get_authorities(&self) -> &[String] {
        &self.authorities
    }

    /// Adds roles to the user (builder pattern).
    pub fn roles(mut self, roles: &[String]) -> Self {
        for role in roles {
            if !self.roles.contains(role) {
                self.roles.push(role.clone());
            }
        }
        self
    }

    /// Adds authorities to the user (builder pattern).
    pub fn authorities(mut self, authorities: &[String]) -> Self {
        for authority in authorities {
            if !self.authorities.contains(authority) {
                self.authorities.push(authority.clone());
            }
        }
        self
    }

    /// Checks if the user has a specific role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Checks if the user has ANY of the specified roles (OR logic).
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|role| self.has_role(role))
    }

    /// Checks if the user has ALL of the specified roles (AND logic).
    pub fn has_all_roles(&self, roles: &[&str]) -> bool {
        roles.iter().all(|role| self.has_role(role))
    }

    /// Checks if the user has a specific authority.
    pub fn has_authority(&self, authority: &str) -> bool {
        self.authorities.iter().any(|a| a == authority)
    }

    /// Checks if the user has ANY of the specified authorities (OR logic).
    pub fn has_any_authority(&self, authorities: &[&str]) -> bool {
        authorities.iter().any(|auth| self.has_authority(auth))
    }

    /// Checks if the user has ALL of the specified authorities (AND logic).
    pub fn has_all_authorities(&self, authorities: &[&str]) -> bool {
        authorities.iter().all(|auth| self.has_authority(auth))
    }

    // Legacy methods for backward compatibility with Vec<String> parameters

    /// Checks if the user has ANY of the specified roles (legacy).
    pub fn has_roles(&self, roles: &[String]) -> bool {
        roles.iter().any(|role| self.roles.contains(role))
    }

    /// Checks if the user has ANY of the specified authorities (legacy).
    #[doc(hidden)]
    pub fn has_authorities(&self, authorities: &[String]) -> bool {
        authorities
            .iter()
            .any(|auth| self.authorities.contains(auth))
    }
}

impl fmt::Display for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "User {{ username: {}, roles: {:?}, authorities: {:?} }}",
            self.username, self.roles, self.authorities
        )
    }
}
