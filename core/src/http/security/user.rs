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

#[cfg(test)]
mod tests {
    use super::*;

    // =============================================================================
    // User Creation Tests
    // =============================================================================

    #[test]
    fn test_user_new() {
        let user = User::new("alice".to_string(), "secret".to_string());
        assert_eq!(user.get_username(), "alice");
        assert_eq!(user.get_password(), "secret");
        assert!(user.get_roles().is_empty());
        assert!(user.get_authorities().is_empty());
    }

    #[test]
    fn test_user_with_encoded_password() {
        let user = User::with_encoded_password("bob", "encoded_hash".to_string());
        assert_eq!(user.get_username(), "bob");
        assert_eq!(user.get_password(), "encoded_hash");
    }

    // =============================================================================
    // Builder Pattern Tests
    // =============================================================================

    #[test]
    fn test_user_roles_builder() {
        let user = User::new("admin".to_string(), "pass".to_string())
            .roles(&["ADMIN".into(), "USER".into()]);

        assert_eq!(user.get_roles().len(), 2);
        assert!(user.get_roles().contains(&"ADMIN".to_string()));
        assert!(user.get_roles().contains(&"USER".to_string()));
    }

    #[test]
    fn test_user_authorities_builder() {
        let user = User::new("admin".to_string(), "pass".to_string())
            .authorities(&["users:read".into(), "users:write".into()]);

        assert_eq!(user.get_authorities().len(), 2);
        assert!(user.get_authorities().contains(&"users:read".to_string()));
        assert!(user.get_authorities().contains(&"users:write".to_string()));
    }

    #[test]
    fn test_user_chained_builder() {
        let user = User::new("admin".to_string(), "pass".to_string())
            .roles(&["ADMIN".into()])
            .authorities(&["api:read".into()]);

        assert_eq!(user.get_roles().len(), 1);
        assert_eq!(user.get_authorities().len(), 1);
    }

    #[test]
    fn test_user_roles_no_duplicates() {
        let user = User::new("admin".to_string(), "pass".to_string())
            .roles(&["ADMIN".into(), "USER".into()])
            .roles(&["ADMIN".into(), "MANAGER".into()]);

        // Should have 3 unique roles: ADMIN, USER, MANAGER (no duplicate ADMIN)
        assert_eq!(user.get_roles().len(), 3);
    }

    #[test]
    fn test_user_authorities_no_duplicates() {
        let user = User::new("admin".to_string(), "pass".to_string())
            .authorities(&["read".into(), "write".into()])
            .authorities(&["read".into(), "delete".into()]);

        // Should have 3 unique authorities
        assert_eq!(user.get_authorities().len(), 3);
    }

    // =============================================================================
    // Role Check Tests
    // =============================================================================

    #[test]
    fn test_has_role() {
        let user = User::new("admin".to_string(), "pass".to_string())
            .roles(&["ADMIN".into(), "USER".into()]);

        assert!(user.has_role("ADMIN"));
        assert!(user.has_role("USER"));
        assert!(!user.has_role("MANAGER"));
    }

    #[test]
    fn test_has_any_role() {
        let user = User::new("user".to_string(), "pass".to_string()).roles(&["USER".into()]);

        assert!(user.has_any_role(&["ADMIN", "USER"]));
        assert!(user.has_any_role(&["USER", "GUEST"]));
        assert!(!user.has_any_role(&["ADMIN", "MANAGER"]));
    }

    #[test]
    fn test_has_all_roles() {
        let user = User::new("admin".to_string(), "pass".to_string()).roles(&[
            "ADMIN".into(),
            "USER".into(),
            "MANAGER".into(),
        ]);

        assert!(user.has_all_roles(&["ADMIN", "USER"]));
        assert!(user.has_all_roles(&["ADMIN", "USER", "MANAGER"]));
        assert!(!user.has_all_roles(&["ADMIN", "SUPERADMIN"]));
    }

    #[test]
    fn test_has_any_role_empty() {
        let user = User::new("guest".to_string(), "pass".to_string());

        assert!(!user.has_any_role(&["ADMIN", "USER"]));
    }

    #[test]
    fn test_has_all_roles_empty_requirement() {
        let user = User::new("user".to_string(), "pass".to_string()).roles(&["USER".into()]);

        // Empty requirement should return true (vacuously true)
        assert!(user.has_all_roles(&[]));
    }

    // =============================================================================
    // Authority Check Tests
    // =============================================================================

    #[test]
    fn test_has_authority() {
        let user = User::new("admin".to_string(), "pass".to_string())
            .authorities(&["users:read".into(), "users:write".into()]);

        assert!(user.has_authority("users:read"));
        assert!(user.has_authority("users:write"));
        assert!(!user.has_authority("users:delete"));
    }

    #[test]
    fn test_has_any_authority() {
        let user =
            User::new("reader".to_string(), "pass".to_string()).authorities(&["read".into()]);

        assert!(user.has_any_authority(&["read", "write"]));
        assert!(!user.has_any_authority(&["write", "delete"]));
    }

    #[test]
    fn test_has_all_authorities() {
        let user = User::new("admin".to_string(), "pass".to_string()).authorities(&[
            "read".into(),
            "write".into(),
            "delete".into(),
        ]);

        assert!(user.has_all_authorities(&["read", "write"]));
        assert!(user.has_all_authorities(&["read", "write", "delete"]));
        assert!(!user.has_all_authorities(&["read", "admin"]));
    }

    // =============================================================================
    // Legacy Method Tests
    // =============================================================================

    #[test]
    fn test_has_roles_legacy() {
        let user = User::new("user".to_string(), "pass".to_string())
            .roles(&["USER".into(), "READER".into()]);

        assert!(user.has_roles(&["USER".to_string()]));
        assert!(user.has_roles(&["ADMIN".to_string(), "USER".to_string()]));
        assert!(!user.has_roles(&["ADMIN".to_string()]));
    }

    #[test]
    fn test_has_authorities_legacy() {
        let user =
            User::new("user".to_string(), "pass".to_string()).authorities(&["api:read".into()]);

        assert!(user.has_authorities(&["api:read".to_string()]));
        assert!(user.has_authorities(&["api:write".to_string(), "api:read".to_string()]));
        assert!(!user.has_authorities(&["api:write".to_string()]));
    }

    // =============================================================================
    // Display Tests
    // =============================================================================

    #[test]
    fn test_display() {
        let user = User::new("admin".to_string(), "secret".to_string())
            .roles(&["ADMIN".into()])
            .authorities(&["read".into()]);

        let display = format!("{}", user);
        assert!(display.contains("admin"));
        assert!(display.contains("ADMIN"));
        assert!(display.contains("read"));
        // Should not contain password
        assert!(!display.contains("secret"));
    }

    // =============================================================================
    // Clone Tests
    // =============================================================================

    #[test]
    fn test_user_clone() {
        let original = User::new("admin".to_string(), "pass".to_string())
            .roles(&["ADMIN".into()])
            .authorities(&["read".into()]);

        let cloned = original.clone();

        assert_eq!(cloned.get_username(), original.get_username());
        assert_eq!(cloned.get_password(), original.get_password());
        assert_eq!(cloned.get_roles(), original.get_roles());
        assert_eq!(cloned.get_authorities(), original.get_authorities());
    }

    // =============================================================================
    // Edge Case Tests
    // =============================================================================

    #[test]
    fn test_empty_username() {
        let user = User::new("".to_string(), "pass".to_string());
        assert_eq!(user.get_username(), "");
    }

    #[test]
    fn test_special_characters_in_role() {
        let user = User::new("user".to_string(), "pass".to_string())
            .roles(&["ROLE:ADMIN".into(), "users:write".into()]);

        assert!(user.has_role("ROLE:ADMIN"));
        assert!(user.has_role("users:write"));
    }

    #[test]
    fn test_case_sensitive_roles() {
        let user = User::new("user".to_string(), "pass".to_string()).roles(&["ADMIN".into()]);

        assert!(user.has_role("ADMIN"));
        assert!(!user.has_role("admin")); // Case sensitive
        assert!(!user.has_role("Admin")); // Case sensitive
    }

    #[test]
    fn test_case_sensitive_authorities() {
        let user =
            User::new("user".to_string(), "pass".to_string()).authorities(&["users:read".into()]);

        assert!(user.has_authority("users:read"));
        assert!(!user.has_authority("USERS:READ")); // Case sensitive
    }
}
