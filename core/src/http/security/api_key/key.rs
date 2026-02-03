//! API Key model.

use std::time::{Duration, SystemTime};

/// Represents an API key with associated metadata and permissions.
///
/// # Example
///
/// ```ignore
/// use actix_security::http::security::api_key::ApiKey;
///
/// let key = ApiKey::new("sk_live_abc123")
///     .name("Production API Key")
///     .owner("service-account@example.com")
///     .roles(vec!["API_USER".into()])
///     .authorities(vec!["api:read".into(), "api:write".into()])
///     .expires_in(Duration::from_secs(86400 * 365)); // 1 year
/// ```
#[derive(Debug, Clone)]
pub struct ApiKey {
    /// The API key value (e.g., "sk_live_abc123")
    key: String,
    /// Human-readable name for the key
    name: Option<String>,
    /// Owner of the key (e.g., email, service name)
    owner: Option<String>,
    /// Roles associated with this key
    roles: Vec<String>,
    /// Authorities (permissions) associated with this key
    authorities: Vec<String>,
    /// Whether the key is enabled
    enabled: bool,
    /// When the key was created
    created_at: SystemTime,
    /// When the key expires (if set)
    expires_at: Option<SystemTime>,
    /// Optional metadata
    metadata: std::collections::HashMap<String, String>,
}

impl ApiKey {
    /// Creates a new API key with the given value.
    ///
    /// # Arguments
    /// * `key` - The API key string
    ///
    /// # Example
    /// ```ignore
    /// let key = ApiKey::new("sk_live_abc123");
    /// ```
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            name: None,
            owner: None,
            roles: Vec::new(),
            authorities: Vec::new(),
            enabled: true,
            created_at: SystemTime::now(),
            expires_at: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Creates a builder for more complex key creation.
    pub fn builder(key: impl Into<String>) -> ApiKeyBuilder {
        ApiKeyBuilder::new(key)
    }

    /// Sets the human-readable name for this key.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the owner of this key.
    pub fn owner(mut self, owner: impl Into<String>) -> Self {
        self.owner = Some(owner.into());
        self
    }

    /// Sets the roles for this key.
    pub fn roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    /// Sets the authorities for this key.
    pub fn authorities(mut self, authorities: Vec<String>) -> Self {
        self.authorities = authorities;
        self
    }

    /// Sets whether the key is enabled.
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Sets the expiration time.
    pub fn expires_at(mut self, expires_at: SystemTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Sets expiration relative to now.
    pub fn expires_in(mut self, duration: Duration) -> Self {
        self.expires_at = Some(SystemTime::now() + duration);
        self
    }

    /// Adds metadata to the key.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    // Getters

    /// Returns the API key value.
    pub fn get_key(&self) -> &str {
        &self.key
    }

    /// Returns the human-readable name.
    pub fn get_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the owner.
    pub fn get_owner(&self) -> Option<&str> {
        self.owner.as_deref()
    }

    /// Returns the roles.
    pub fn get_roles(&self) -> &[String] {
        &self.roles
    }

    /// Returns the authorities.
    pub fn get_authorities(&self) -> &[String] {
        &self.authorities
    }

    /// Returns whether the key is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns when the key was created.
    pub fn get_created_at(&self) -> SystemTime {
        self.created_at
    }

    /// Returns when the key expires.
    pub fn get_expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }

    /// Returns the metadata.
    pub fn get_metadata(&self) -> &std::collections::HashMap<String, String> {
        &self.metadata
    }

    /// Checks if the key has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            SystemTime::now() > expires_at
        } else {
            false
        }
    }

    /// Checks if the key is valid (enabled and not expired).
    pub fn is_valid(&self) -> bool {
        self.enabled && !self.is_expired()
    }

    /// Checks if the key has the specified role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Checks if the key has any of the specified roles.
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|role| self.has_role(role))
    }

    /// Checks if the key has the specified authority.
    pub fn has_authority(&self, authority: &str) -> bool {
        self.authorities.iter().any(|a| a == authority)
    }

    /// Checks if the key has any of the specified authorities.
    pub fn has_any_authority(&self, authorities: &[&str]) -> bool {
        authorities.iter().any(|auth| self.has_authority(auth))
    }
}

/// Builder for `ApiKey`.
#[derive(Debug, Clone)]
pub struct ApiKeyBuilder {
    key: ApiKey,
}

impl ApiKeyBuilder {
    /// Creates a new builder.
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: ApiKey::new(key),
        }
    }

    /// Sets the human-readable name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.key.name = Some(name.into());
        self
    }

    /// Sets the owner.
    pub fn owner(mut self, owner: impl Into<String>) -> Self {
        self.key.owner = Some(owner.into());
        self
    }

    /// Sets the roles.
    pub fn roles(mut self, roles: Vec<String>) -> Self {
        self.key.roles = roles;
        self
    }

    /// Adds a role.
    pub fn role(mut self, role: impl Into<String>) -> Self {
        self.key.roles.push(role.into());
        self
    }

    /// Sets the authorities.
    pub fn authorities(mut self, authorities: Vec<String>) -> Self {
        self.key.authorities = authorities;
        self
    }

    /// Adds an authority.
    pub fn authority(mut self, authority: impl Into<String>) -> Self {
        self.key.authorities.push(authority.into());
        self
    }

    /// Sets whether the key is enabled.
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.key.enabled = enabled;
        self
    }

    /// Sets the expiration time.
    pub fn expires_at(mut self, expires_at: SystemTime) -> Self {
        self.key.expires_at = Some(expires_at);
        self
    }

    /// Sets expiration relative to now.
    pub fn expires_in(mut self, duration: Duration) -> Self {
        self.key.expires_at = Some(SystemTime::now() + duration);
        self
    }

    /// Adds metadata.
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.key.metadata.insert(key.into(), value.into());
        self
    }

    /// Builds the API key.
    pub fn build(self) -> ApiKey {
        self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_creation() {
        let key = ApiKey::new("sk_test_123");
        assert_eq!(key.get_key(), "sk_test_123");
        assert!(key.is_enabled());
        assert!(!key.is_expired());
        assert!(key.is_valid());
    }

    #[test]
    fn test_api_key_with_roles() {
        let key = ApiKey::new("sk_test_123").roles(vec!["USER".into(), "ADMIN".into()]);

        assert!(key.has_role("USER"));
        assert!(key.has_role("ADMIN"));
        assert!(!key.has_role("SUPER_ADMIN"));
        assert!(key.has_any_role(&["USER", "GUEST"]));
    }

    #[test]
    fn test_api_key_with_authorities() {
        let key =
            ApiKey::new("sk_test_123").authorities(vec!["api:read".into(), "api:write".into()]);

        assert!(key.has_authority("api:read"));
        assert!(key.has_authority("api:write"));
        assert!(!key.has_authority("api:admin"));
        assert!(key.has_any_authority(&["api:read", "api:delete"]));
    }

    #[test]
    fn test_api_key_disabled() {
        let key = ApiKey::new("sk_test_123").enabled(false);
        assert!(!key.is_enabled());
        assert!(!key.is_valid());
    }

    #[test]
    fn test_api_key_expired() {
        let key = ApiKey::new("sk_test_123").expires_at(SystemTime::UNIX_EPOCH); // Already expired

        assert!(key.is_expired());
        assert!(!key.is_valid());
    }

    #[test]
    fn test_api_key_builder() {
        let key = ApiKey::builder("sk_test_123")
            .name("Test Key")
            .owner("test@example.com")
            .role("USER")
            .role("ADMIN")
            .authority("api:read")
            .metadata("environment", "test")
            .build();

        assert_eq!(key.get_name(), Some("Test Key"));
        assert_eq!(key.get_owner(), Some("test@example.com"));
        assert!(key.has_role("USER"));
        assert!(key.has_role("ADMIN"));
        assert!(key.has_authority("api:read"));
        assert_eq!(
            key.get_metadata().get("environment"),
            Some(&"test".to_string())
        );
    }
}
