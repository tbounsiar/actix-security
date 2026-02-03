//! API Key repository trait and implementations.

use super::key::ApiKey;
use std::collections::HashMap;
use std::sync::RwLock;

/// Trait for loading API keys.
///
/// Implement this trait to provide custom storage backends for API keys
/// (e.g., database, Redis, external service).
///
/// # Example
///
/// ```ignore
/// use actix_security::http::security::api_key::{ApiKey, ApiKeyRepository};
///
/// struct DatabaseApiKeyRepository {
///     pool: DbPool,
/// }
///
/// impl ApiKeyRepository for DatabaseApiKeyRepository {
///     fn find_by_key(&self, key: &str) -> Option<ApiKey> {
///         // Query database for the API key
///         self.pool.query("SELECT * FROM api_keys WHERE key = ?", &[key])
///             .ok()
///             .map(|row| ApiKey::new(row.key)
///                 .name(row.name)
///                 .owner(row.owner)
///                 .roles(row.roles)
///                 .authorities(row.authorities)
///                 .enabled(row.enabled))
///     }
/// }
/// ```
pub trait ApiKeyRepository: Send + Sync {
    /// Finds an API key by its value.
    ///
    /// Returns `Some(ApiKey)` if found, `None` otherwise.
    fn find_by_key(&self, key: &str) -> Option<ApiKey>;
}

/// In-memory implementation of `ApiKeyRepository`.
///
/// Useful for development, testing, and simple applications.
///
/// # Example
///
/// ```ignore
/// use actix_security::http::security::api_key::{ApiKey, InMemoryApiKeyRepository};
///
/// let repository = InMemoryApiKeyRepository::new()
///     .with_key(ApiKey::new("sk_live_abc123")
///         .name("Production Key")
///         .roles(vec!["API_USER".into()])
///         .authorities(vec!["api:read".into()]))
///     .with_key(ApiKey::new("sk_test_xyz789")
///         .name("Test Key")
///         .roles(vec!["API_USER".into(), "API_ADMIN".into()])
///         .authorities(vec!["api:read".into(), "api:write".into()]));
/// ```
#[derive(Debug)]
pub struct InMemoryApiKeyRepository {
    keys: RwLock<HashMap<String, ApiKey>>,
}

impl Default for InMemoryApiKeyRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryApiKeyRepository {
    /// Creates an empty repository.
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }

    /// Adds an API key to the repository.
    pub fn with_key(self, key: ApiKey) -> Self {
        self.add_key(key);
        self
    }

    /// Adds an API key to the repository.
    pub fn add_key(&self, key: ApiKey) {
        let mut keys = self.keys.write().unwrap();
        keys.insert(key.get_key().to_string(), key);
    }

    /// Removes an API key from the repository.
    pub fn remove_key(&self, key: &str) -> Option<ApiKey> {
        let mut keys = self.keys.write().unwrap();
        keys.remove(key)
    }

    /// Returns the number of keys in the repository.
    pub fn len(&self) -> usize {
        let keys = self.keys.read().unwrap();
        keys.len()
    }

    /// Returns true if the repository is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clears all keys from the repository.
    pub fn clear(&self) {
        let mut keys = self.keys.write().unwrap();
        keys.clear();
    }

    /// Returns all API keys in the repository.
    pub fn get_all_keys(&self) -> Vec<ApiKey> {
        let keys = self.keys.read().unwrap();
        keys.values().cloned().collect()
    }
}

impl ApiKeyRepository for InMemoryApiKeyRepository {
    fn find_by_key(&self, key: &str) -> Option<ApiKey> {
        let keys = self.keys.read().unwrap();
        keys.get(key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_repository() {
        let repo = InMemoryApiKeyRepository::new();
        assert!(repo.is_empty());
        assert_eq!(repo.len(), 0);
        assert!(repo.find_by_key("nonexistent").is_none());
    }

    #[test]
    fn test_add_and_find_key() {
        let repo =
            InMemoryApiKeyRepository::new().with_key(ApiKey::new("sk_test_123").name("Test Key"));

        assert_eq!(repo.len(), 1);

        let found = repo.find_by_key("sk_test_123");
        assert!(found.is_some());

        let key = found.unwrap();
        assert_eq!(key.get_key(), "sk_test_123");
        assert_eq!(key.get_name(), Some("Test Key"));
    }

    #[test]
    fn test_add_key_method() {
        let repo = InMemoryApiKeyRepository::new();
        repo.add_key(ApiKey::new("sk_test_123"));
        assert_eq!(repo.len(), 1);
    }

    #[test]
    fn test_remove_key() {
        let repo = InMemoryApiKeyRepository::new().with_key(ApiKey::new("sk_test_123"));

        let removed = repo.remove_key("sk_test_123");
        assert!(removed.is_some());
        assert!(repo.is_empty());
    }

    #[test]
    fn test_clear() {
        let repo = InMemoryApiKeyRepository::new()
            .with_key(ApiKey::new("key1"))
            .with_key(ApiKey::new("key2"))
            .with_key(ApiKey::new("key3"));

        assert_eq!(repo.len(), 3);
        repo.clear();
        assert!(repo.is_empty());
    }

    #[test]
    fn test_get_all_keys() {
        let repo = InMemoryApiKeyRepository::new()
            .with_key(ApiKey::new("key1"))
            .with_key(ApiKey::new("key2"));

        let all_keys = repo.get_all_keys();
        assert_eq!(all_keys.len(), 2);
    }

    #[test]
    fn test_key_with_full_metadata() {
        let repo = InMemoryApiKeyRepository::new().with_key(
            ApiKey::new("sk_live_abc123")
                .name("Production API Key")
                .owner("admin@example.com")
                .roles(vec!["API_USER".into(), "API_ADMIN".into()])
                .authorities(vec!["api:read".into(), "api:write".into()])
                .with_metadata("environment", "production"),
        );

        let found = repo.find_by_key("sk_live_abc123").unwrap();
        assert_eq!(found.get_name(), Some("Production API Key"));
        assert_eq!(found.get_owner(), Some("admin@example.com"));
        assert!(found.has_role("API_USER"));
        assert!(found.has_role("API_ADMIN"));
        assert!(found.has_authority("api:read"));
        assert!(found.has_authority("api:write"));
        assert_eq!(
            found.get_metadata().get("environment"),
            Some(&"production".to_string())
        );
    }
}
