//! LDAP Authentication module.
//!
//! Provides LDAP/Active Directory authentication support.
//!
//! # Spring Security Equivalent
//! `org.springframework.security.ldap` package including:
//! - `LdapAuthenticationProvider`
//! - `LdapUserDetailsService`
//! - `ActiveDirectoryLdapAuthenticationProvider`
//!
//! # Example
//!
//! ```ignore
//! use actix_security::http::security::ldap::{LdapConfig, LdapAuthenticator};
//!
//! let ldap = LdapConfig::new("ldap://localhost:389")
//!     .base_dn("dc=example,dc=com")
//!     .user_search_filter("(uid={0})")
//!     .bind_dn("cn=admin,dc=example,dc=com")
//!     .bind_password("secret");
//!
//! let authenticator = LdapAuthenticator::new(ldap);
//! ```

use crate::http::security::user::User;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Type alias for mock LDAP user store: (password, attributes, groups)
type MockUserEntry = (String, HashMap<String, Vec<String>>, Vec<String>);

/// LDAP connection configuration.
#[derive(Debug, Clone)]
pub struct LdapConfig {
    /// LDAP server URL (e.g., "ldap://localhost:389" or "ldaps://localhost:636")
    pub url: String,
    /// Base DN for searches (e.g., "dc=example,dc=com")
    pub base_dn: String,
    /// User search base (relative to base_dn)
    pub user_search_base: String,
    /// User search filter (use {0} for username placeholder)
    pub user_search_filter: String,
    /// Group search base (relative to base_dn)
    pub group_search_base: String,
    /// Group search filter (use {0} for user DN placeholder)
    pub group_search_filter: String,
    /// Group role attribute (e.g., "cn")
    pub group_role_attribute: String,
    /// Bind DN for searching (optional, for bind-then-search)
    pub bind_dn: Option<String>,
    /// Bind password
    pub bind_password: Option<String>,
    /// User DN pattern for direct bind (use {0} for username)
    pub user_dn_pattern: Option<String>,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Operation timeout
    pub operation_timeout: Duration,
    /// Use StartTLS
    pub use_starttls: bool,
    /// Role prefix (e.g., "ROLE_")
    pub role_prefix: String,
    /// Convert roles to uppercase
    pub convert_to_uppercase: bool,
    /// Username attribute in LDAP
    pub username_attribute: String,
    /// Email attribute in LDAP
    pub email_attribute: String,
    /// Display name attribute in LDAP
    pub display_name_attribute: String,
    /// Custom attribute mappings
    pub attribute_mappings: HashMap<String, String>,
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            url: "ldap://localhost:389".to_string(),
            base_dn: String::new(),
            user_search_base: "ou=users".to_string(),
            user_search_filter: "(uid={0})".to_string(),
            group_search_base: "ou=groups".to_string(),
            group_search_filter: "(member={0})".to_string(),
            group_role_attribute: "cn".to_string(),
            bind_dn: None,
            bind_password: None,
            user_dn_pattern: None,
            connect_timeout: Duration::from_secs(5),
            operation_timeout: Duration::from_secs(10),
            use_starttls: false,
            role_prefix: "ROLE_".to_string(),
            convert_to_uppercase: true,
            username_attribute: "uid".to_string(),
            email_attribute: "mail".to_string(),
            display_name_attribute: "cn".to_string(),
            attribute_mappings: HashMap::new(),
        }
    }
}

impl LdapConfig {
    /// Create a new LDAP configuration with the server URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ..Default::default()
        }
    }

    /// Create configuration for Active Directory.
    pub fn active_directory(url: impl Into<String>, domain: impl Into<String>) -> Self {
        let domain = domain.into();
        let base_dn = domain
            .split('.')
            .map(|part| format!("dc={}", part))
            .collect::<Vec<_>>()
            .join(",");

        Self {
            url: url.into(),
            base_dn,
            user_search_filter: "(sAMAccountName={0})".to_string(),
            group_search_filter: "(member:1.2.840.113556.1.4.1941:={0})".to_string(),
            username_attribute: "sAMAccountName".to_string(),
            display_name_attribute: "displayName".to_string(),
            ..Default::default()
        }
    }

    /// Set the base DN.
    pub fn base_dn(mut self, dn: impl Into<String>) -> Self {
        self.base_dn = dn.into();
        self
    }

    /// Set the user search base (relative to base DN).
    pub fn user_search_base(mut self, base: impl Into<String>) -> Self {
        self.user_search_base = base.into();
        self
    }

    /// Set the user search filter.
    pub fn user_search_filter(mut self, filter: impl Into<String>) -> Self {
        self.user_search_filter = filter.into();
        self
    }

    /// Set the group search base (relative to base DN).
    pub fn group_search_base(mut self, base: impl Into<String>) -> Self {
        self.group_search_base = base.into();
        self
    }

    /// Set the group search filter.
    pub fn group_search_filter(mut self, filter: impl Into<String>) -> Self {
        self.group_search_filter = filter.into();
        self
    }

    /// Set the bind DN for searching.
    pub fn bind_dn(mut self, dn: impl Into<String>) -> Self {
        self.bind_dn = Some(dn.into());
        self
    }

    /// Set the bind password.
    pub fn bind_password(mut self, password: impl Into<String>) -> Self {
        self.bind_password = Some(password.into());
        self
    }

    /// Set the user DN pattern for direct bind authentication.
    pub fn user_dn_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.user_dn_pattern = Some(pattern.into());
        self
    }

    /// Set connection timeout.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set operation timeout.
    pub fn operation_timeout(mut self, timeout: Duration) -> Self {
        self.operation_timeout = timeout;
        self
    }

    /// Enable StartTLS.
    pub fn use_starttls(mut self, use_tls: bool) -> Self {
        self.use_starttls = use_tls;
        self
    }

    /// Set the role prefix.
    pub fn role_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.role_prefix = prefix.into();
        self
    }

    /// Set whether to convert roles to uppercase.
    pub fn convert_to_uppercase(mut self, convert: bool) -> Self {
        self.convert_to_uppercase = convert;
        self
    }

    /// Add a custom attribute mapping.
    pub fn map_attribute(
        mut self,
        ldap_attr: impl Into<String>,
        user_attr: impl Into<String>,
    ) -> Self {
        self.attribute_mappings
            .insert(ldap_attr.into(), user_attr.into());
        self
    }

    /// Get the full user search base DN.
    pub fn full_user_search_base(&self) -> String {
        if self.user_search_base.is_empty() {
            self.base_dn.clone()
        } else {
            format!("{},{}", self.user_search_base, self.base_dn)
        }
    }

    /// Get the full group search base DN.
    pub fn full_group_search_base(&self) -> String {
        if self.group_search_base.is_empty() {
            self.base_dn.clone()
        } else {
            format!("{},{}", self.group_search_base, self.base_dn)
        }
    }

    /// Build the user search filter with username substituted.
    pub fn build_user_filter(&self, username: &str) -> String {
        self.user_search_filter.replace("{0}", username)
    }

    /// Build the group search filter with user DN substituted.
    pub fn build_group_filter(&self, user_dn: &str) -> String {
        self.group_search_filter.replace("{0}", user_dn)
    }

    /// Build the user DN from pattern.
    pub fn build_user_dn(&self, username: &str) -> Option<String> {
        self.user_dn_pattern
            .as_ref()
            .map(|pattern| pattern.replace("{0}", username))
    }
}

/// LDAP authentication result.
#[derive(Debug, Clone)]
pub struct LdapAuthResult {
    /// Whether authentication succeeded
    pub success: bool,
    /// User DN (if found)
    pub user_dn: Option<String>,
    /// User attributes
    pub attributes: HashMap<String, Vec<String>>,
    /// Group DNs
    pub groups: Vec<String>,
    /// Error message (if failed)
    pub error: Option<String>,
}

impl LdapAuthResult {
    /// Create a successful result.
    pub fn success(user_dn: String, attributes: HashMap<String, Vec<String>>) -> Self {
        Self {
            success: true,
            user_dn: Some(user_dn),
            attributes,
            groups: Vec::new(),
            error: None,
        }
    }

    /// Create a failed result.
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            user_dn: None,
            attributes: HashMap::new(),
            groups: Vec::new(),
            error: Some(error.into()),
        }
    }

    /// Add groups to the result.
    pub fn with_groups(mut self, groups: Vec<String>) -> Self {
        self.groups = groups;
        self
    }

    /// Get a single attribute value.
    pub fn get_attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .get(name)
            .and_then(|values| values.first())
            .map(|s| s.as_str())
    }

    /// Get all values for an attribute.
    pub fn get_attribute_values(&self, name: &str) -> Option<&Vec<String>> {
        self.attributes.get(name)
    }
}

/// LDAP authentication error.
#[derive(Debug, Clone)]
pub enum LdapError {
    /// Connection failed
    ConnectionFailed(String),
    /// Bind failed (invalid credentials for service account)
    BindFailed(String),
    /// User not found
    UserNotFound(String),
    /// Authentication failed (invalid password)
    AuthenticationFailed(String),
    /// Search failed
    SearchFailed(String),
    /// Configuration error
    ConfigurationError(String),
    /// Timeout
    Timeout,
    /// TLS error
    TlsError(String),
}

impl std::fmt::Display for LdapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LdapError::ConnectionFailed(msg) => write!(f, "LDAP connection failed: {}", msg),
            LdapError::BindFailed(msg) => write!(f, "LDAP bind failed: {}", msg),
            LdapError::UserNotFound(msg) => write!(f, "User not found: {}", msg),
            LdapError::AuthenticationFailed(msg) => write!(f, "Authentication failed: {}", msg),
            LdapError::SearchFailed(msg) => write!(f, "LDAP search failed: {}", msg),
            LdapError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            LdapError::Timeout => write!(f, "LDAP operation timed out"),
            LdapError::TlsError(msg) => write!(f, "TLS error: {}", msg),
        }
    }
}

impl std::error::Error for LdapError {}

/// Trait for LDAP operations.
///
/// This trait abstracts LDAP operations to allow for different implementations
/// (real LDAP client, mock for testing, etc.)
#[cfg_attr(feature = "ldap", async_trait::async_trait)]
pub trait LdapOperations: Send + Sync {
    /// Connect to the LDAP server.
    async fn connect(&self) -> Result<(), LdapError>;

    /// Bind with credentials.
    async fn bind(&self, dn: &str, password: &str) -> Result<(), LdapError>;

    /// Search for entries.
    async fn search(
        &self,
        base: &str,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<LdapAuthResult>, LdapError>;

    /// Authenticate a user and return their info.
    async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<LdapAuthResult, LdapError>;
}

/// LDAP Authenticator for actix-security.
///
/// # Spring Security Equivalent
/// `LdapAuthenticationProvider`
#[derive(Clone)]
pub struct LdapAuthenticator {
    config: Arc<LdapConfig>,
    #[cfg(feature = "ldap")]
    client: Arc<dyn LdapOperations>,
}

impl LdapAuthenticator {
    /// Create a new LDAP authenticator with configuration.
    #[cfg(feature = "ldap")]
    pub fn new<C: LdapOperations + 'static>(config: LdapConfig, client: C) -> Self {
        Self {
            config: Arc::new(config),
            client: Arc::new(client),
        }
    }

    /// Create with just configuration (requires setting client later or using mock).
    pub fn with_config(config: LdapConfig) -> Self {
        Self {
            config: Arc::new(config),
            #[cfg(feature = "ldap")]
            client: Arc::new(MockLdapClient::new()),
        }
    }

    /// Get the configuration.
    pub fn config(&self) -> &LdapConfig {
        &self.config
    }

    /// Authenticate a user and return a User object.
    #[cfg(feature = "ldap")]
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<User, LdapError> {
        let result = self.client.authenticate(username, password).await?;

        if !result.success {
            return Err(LdapError::AuthenticationFailed(
                result.error.unwrap_or_else(|| "Unknown error".to_string()),
            ));
        }

        // Build user from LDAP result
        let user = self.build_user_from_result(username, &result);
        Ok(user)
    }

    /// Build a User from LDAP authentication result.
    fn build_user_from_result(&self, username: &str, result: &LdapAuthResult) -> User {
        // Extract roles from groups
        let roles: Vec<String> = result
            .groups
            .iter()
            .filter_map(|group_dn| {
                // Extract CN from DN
                group_dn
                    .split(',')
                    .next()
                    .and_then(|cn_part| cn_part.strip_prefix("cn=").or(cn_part.strip_prefix("CN=")))
                    .map(|cn| {
                        let role = if self.config.convert_to_uppercase {
                            cn.to_uppercase()
                        } else {
                            cn.to_string()
                        };
                        format!("{}{}", self.config.role_prefix, role)
                    })
            })
            .collect();

        // Get display name (stored for future use)
        let _display_name = result
            .get_attribute(&self.config.display_name_attribute)
            .unwrap_or(username);

        // Create user
        let mut user = User::new(username.to_string(), String::new());

        // Set roles
        if !roles.is_empty() {
            user = user.roles(&roles);
        }

        // Store additional attributes
        if let Some(email) = result.get_attribute(&self.config.email_attribute) {
            user = user.authorities(&[format!("email:{}", email)]);
        }

        // Store DN as authority for reference
        if let Some(ref dn) = result.user_dn {
            user = user.authorities(&[format!("dn:{}", dn)]);
        }

        user
    }
}

/// Mock LDAP client for testing.
#[derive(Default)]
pub struct MockLdapClient {
    users: std::sync::RwLock<HashMap<String, MockUserEntry>>,
}

impl MockLdapClient {
    /// Create a new mock client.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a test user.
    pub fn add_user(
        &self,
        username: &str,
        password: &str,
        attributes: HashMap<String, Vec<String>>,
        groups: Vec<String>,
    ) {
        let mut users = self.users.write().unwrap();
        users.insert(
            username.to_string(),
            (password.to_string(), attributes, groups),
        );
    }
}

#[cfg_attr(feature = "ldap", async_trait::async_trait)]
impl LdapOperations for MockLdapClient {
    async fn connect(&self) -> Result<(), LdapError> {
        Ok(())
    }

    async fn bind(&self, _dn: &str, _password: &str) -> Result<(), LdapError> {
        Ok(())
    }

    async fn search(
        &self,
        _base: &str,
        _filter: &str,
        _attrs: &[&str],
    ) -> Result<Vec<LdapAuthResult>, LdapError> {
        Ok(Vec::new())
    }

    async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<LdapAuthResult, LdapError> {
        let users = self.users.read().unwrap();

        match users.get(username) {
            Some((stored_password, attributes, groups)) if stored_password == password => {
                Ok(LdapAuthResult::success(
                    format!("uid={},ou=users,dc=example,dc=com", username),
                    attributes.clone(),
                )
                .with_groups(groups.clone()))
            }
            Some(_) => Err(LdapError::AuthenticationFailed(
                "Invalid password".to_string(),
            )),
            None => Err(LdapError::UserNotFound(username.to_string())),
        }
    }
}

/// LDAP context mapper for custom user creation.
pub trait LdapContextMapper: Send + Sync {
    /// Map LDAP result to a User.
    fn map_user(&self, username: &str, result: &LdapAuthResult, config: &LdapConfig) -> User;
}

/// Default context mapper.
#[derive(Default)]
pub struct DefaultLdapContextMapper;

impl LdapContextMapper for DefaultLdapContextMapper {
    fn map_user(&self, username: &str, result: &LdapAuthResult, config: &LdapConfig) -> User {
        let roles: Vec<String> = result
            .groups
            .iter()
            .filter_map(|group_dn| {
                group_dn
                    .split(',')
                    .next()
                    .and_then(|cn_part| cn_part.strip_prefix("cn=").or(cn_part.strip_prefix("CN=")))
                    .map(|cn| {
                        let role = if config.convert_to_uppercase {
                            cn.to_uppercase()
                        } else {
                            cn.to_string()
                        };
                        format!("{}{}", config.role_prefix, role)
                    })
            })
            .collect();

        User::new(username.to_string(), String::new()).roles(&roles)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_config_builder() {
        let config = LdapConfig::new("ldap://localhost:389")
            .base_dn("dc=example,dc=com")
            .user_search_filter("(uid={0})")
            .bind_dn("cn=admin,dc=example,dc=com")
            .bind_password("secret");

        assert_eq!(config.url, "ldap://localhost:389");
        assert_eq!(config.base_dn, "dc=example,dc=com");
        assert_eq!(config.bind_dn, Some("cn=admin,dc=example,dc=com".to_string()));
    }

    #[test]
    fn test_active_directory_config() {
        let config = LdapConfig::active_directory("ldap://dc.example.com", "example.com");

        assert_eq!(config.base_dn, "dc=example,dc=com");
        assert_eq!(config.user_search_filter, "(sAMAccountName={0})");
        assert_eq!(config.username_attribute, "sAMAccountName");
    }

    #[test]
    fn test_build_user_filter() {
        let config = LdapConfig::new("ldap://localhost").user_search_filter("(uid={0})");

        assert_eq!(config.build_user_filter("john"), "(uid=john)");
    }

    #[test]
    fn test_build_user_dn() {
        let config =
            LdapConfig::new("ldap://localhost").user_dn_pattern("uid={0},ou=users,dc=example,dc=com");

        assert_eq!(
            config.build_user_dn("john"),
            Some("uid=john,ou=users,dc=example,dc=com".to_string())
        );
    }

    #[test]
    fn test_ldap_auth_result() {
        let mut attrs = HashMap::new();
        attrs.insert("cn".to_string(), vec!["John Doe".to_string()]);
        attrs.insert("mail".to_string(), vec!["john@example.com".to_string()]);

        let result = LdapAuthResult::success("uid=john,dc=example,dc=com".to_string(), attrs)
            .with_groups(vec!["cn=admins,ou=groups,dc=example,dc=com".to_string()]);

        assert!(result.success);
        assert_eq!(result.get_attribute("cn"), Some("John Doe"));
        assert_eq!(result.get_attribute("mail"), Some("john@example.com"));
        assert_eq!(result.groups.len(), 1);
    }

    #[tokio::test]
    async fn test_mock_ldap_client() {
        let client = MockLdapClient::new();

        let mut attrs = HashMap::new();
        attrs.insert("cn".to_string(), vec!["Test User".to_string()]);

        client.add_user(
            "testuser",
            "password123",
            attrs,
            vec!["cn=users,ou=groups,dc=example,dc=com".to_string()],
        );

        // Test successful auth
        let result = client.authenticate("testuser", "password123").await;
        assert!(result.is_ok());

        // Test failed auth
        let result = client.authenticate("testuser", "wrongpass").await;
        assert!(result.is_err());

        // Test user not found
        let result = client.authenticate("unknown", "password").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_ldap_error_display() {
        let err = LdapError::ConnectionFailed("Connection refused".to_string());
        assert!(err.to_string().contains("Connection refused"));

        let err = LdapError::UserNotFound("john".to_string());
        assert!(err.to_string().contains("john"));
    }
}
