//! User Details Service for loading users from any data source.
//!
//! # Spring Security Equivalent
//! Similar to Spring Security's `UserDetailsService` and `UserDetailsManager` interfaces.
//!
//! # Features
//! - Async trait for loading users
//! - Support for any data source (database, LDAP, API, etc.)
//! - User management operations (create, update, delete)
//! - Caching layer support
//!
//! # Example
//! ```rust,ignore
//! use actix_security_core::http::security::user_details::{UserDetailsService, UserDetailsError};
//! use async_trait::async_trait;
//!
//! struct MyUserDetailsService {
//!     pool: PgPool,
//! }
//!
//! #[async_trait]
//! impl UserDetailsService for MyUserDetailsService {
//!     async fn load_user_by_username(&self, username: &str) -> Result<Option<User>, UserDetailsError> {
//!         // Load from database...
//!         Ok(Some(user))
//!     }
//! }
//! ```

use crate::http::security::crypto::PasswordEncoder;
use crate::http::security::User;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

// =============================================================================
// User Details Error
// =============================================================================

/// Errors that can occur when loading or managing user details.
#[derive(Debug)]
pub enum UserDetailsError {
    /// User not found
    NotFound,
    /// User already exists
    AlreadyExists,
    /// Invalid credentials
    InvalidCredentials,
    /// Account is disabled
    AccountDisabled,
    /// Account is locked
    AccountLocked,
    /// Account is expired
    AccountExpired,
    /// Credentials are expired
    CredentialsExpired,
    /// Database or storage error
    StorageError(String),
    /// Other error
    Other(String),
}

impl std::fmt::Display for UserDetailsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserDetailsError::NotFound => write!(f, "User not found"),
            UserDetailsError::AlreadyExists => write!(f, "User already exists"),
            UserDetailsError::InvalidCredentials => write!(f, "Invalid credentials"),
            UserDetailsError::AccountDisabled => write!(f, "Account is disabled"),
            UserDetailsError::AccountLocked => write!(f, "Account is locked"),
            UserDetailsError::AccountExpired => write!(f, "Account is expired"),
            UserDetailsError::CredentialsExpired => write!(f, "Credentials are expired"),
            UserDetailsError::StorageError(e) => write!(f, "Storage error: {}", e),
            UserDetailsError::Other(e) => write!(f, "Error: {}", e),
        }
    }
}

impl std::error::Error for UserDetailsError {}

// =============================================================================
// User Details Service Trait
// =============================================================================

/// Async trait for loading user details from any data source.
///
/// # Spring Security Equivalent
/// Similar to `UserDetailsService` in Spring Security.
///
/// # Example
/// ```rust,ignore
/// use actix_security_core::http::security::user_details::{UserDetailsService, UserDetailsError};
/// use async_trait::async_trait;
///
/// struct DatabaseUserDetailsService {
///     pool: sqlx::PgPool,
/// }
///
/// #[async_trait]
/// impl UserDetailsService for DatabaseUserDetailsService {
///     async fn load_user_by_username(&self, username: &str) -> Result<Option<User>, UserDetailsError> {
///         let row = sqlx::query!("SELECT * FROM users WHERE username = $1", username)
///             .fetch_optional(&self.pool)
///             .await
///             .map_err(|e| UserDetailsError::StorageError(e.to_string()))?;
///
///         Ok(row.map(|r| User::with_encoded_password(&r.username, r.password)
///             .roles(&r.roles.split(',').map(String::from).collect::<Vec<_>>())))
///     }
/// }
/// ```
#[async_trait]
pub trait UserDetailsService: Send + Sync {
    /// Load user by username.
    ///
    /// Returns `Ok(Some(user))` if found, `Ok(None)` if not found,
    /// or `Err(...)` if an error occurred.
    async fn load_user_by_username(&self, username: &str)
        -> Result<Option<User>, UserDetailsError>;

    /// Check if a user exists.
    async fn user_exists(&self, username: &str) -> Result<bool, UserDetailsError> {
        Ok(self.load_user_by_username(username).await?.is_some())
    }
}

// =============================================================================
// User Details Manager Trait
// =============================================================================

/// Extended trait for managing users (CRUD operations).
///
/// # Spring Security Equivalent
/// Similar to `UserDetailsManager` in Spring Security.
///
/// # Example
/// ```rust,ignore
/// #[async_trait]
/// impl UserDetailsManager for DatabaseUserDetailsService {
///     async fn create_user(&self, user: &User) -> Result<(), UserDetailsError> {
///         sqlx::query!("INSERT INTO users ...")
///             .execute(&self.pool)
///             .await
///             .map_err(|e| UserDetailsError::StorageError(e.to_string()))?;
///         Ok(())
///     }
///     // ... other methods
/// }
/// ```
#[async_trait]
pub trait UserDetailsManager: UserDetailsService {
    /// Create a new user.
    async fn create_user(&self, user: &User) -> Result<(), UserDetailsError>;

    /// Update an existing user.
    async fn update_user(&self, user: &User) -> Result<(), UserDetailsError>;

    /// Delete a user by username.
    async fn delete_user(&self, username: &str) -> Result<(), UserDetailsError>;

    /// Change user's password.
    ///
    /// # Arguments
    /// * `username` - The username
    /// * `old_password` - The current password (for verification)
    /// * `new_password` - The new password (should be encoded)
    async fn change_password(
        &self,
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), UserDetailsError>;
}

// =============================================================================
// In-Memory User Details Service
// =============================================================================

/// In-memory implementation of UserDetailsService.
///
/// Useful for testing or small applications.
#[derive(Clone)]
pub struct InMemoryUserDetailsService {
    users: Arc<RwLock<HashMap<String, User>>>,
}

impl Default for InMemoryUserDetailsService {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryUserDetailsService {
    /// Create a new in-memory service.
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a user.
    pub async fn add_user(&self, user: User) {
        let mut users = self.users.write().await;
        users.insert(user.get_username().to_string(), user);
    }

    /// Add multiple users.
    pub async fn add_users(&self, users: Vec<User>) {
        let mut store = self.users.write().await;
        for user in users {
            store.insert(user.get_username().to_string(), user);
        }
    }
}

#[async_trait]
impl UserDetailsService for InMemoryUserDetailsService {
    async fn load_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<User>, UserDetailsError> {
        let users = self.users.read().await;
        Ok(users.get(username).cloned())
    }
}

#[async_trait]
impl UserDetailsManager for InMemoryUserDetailsService {
    async fn create_user(&self, user: &User) -> Result<(), UserDetailsError> {
        let mut users = self.users.write().await;
        let username = user.get_username().to_string();
        if users.contains_key(&username) {
            return Err(UserDetailsError::AlreadyExists);
        }
        users.insert(username, user.clone());
        Ok(())
    }

    async fn update_user(&self, user: &User) -> Result<(), UserDetailsError> {
        let mut users = self.users.write().await;
        let username = user.get_username().to_string();
        if !users.contains_key(&username) {
            return Err(UserDetailsError::NotFound);
        }
        users.insert(username, user.clone());
        Ok(())
    }

    async fn delete_user(&self, username: &str) -> Result<(), UserDetailsError> {
        let mut users = self.users.write().await;
        if users.remove(username).is_none() {
            return Err(UserDetailsError::NotFound);
        }
        Ok(())
    }

    async fn change_password(
        &self,
        username: &str,
        _old_password: &str,
        new_password: &str,
    ) -> Result<(), UserDetailsError> {
        let mut users = self.users.write().await;
        match users.get_mut(username) {
            Some(user) => {
                // Create new user with updated password
                let updated = User::new(user.get_username().to_string(), new_password.to_string())
                    .roles(user.get_roles())
                    .authorities(user.get_authorities());
                *user = updated;
                Ok(())
            }
            None => Err(UserDetailsError::NotFound),
        }
    }
}

// =============================================================================
// Caching User Details Service
// =============================================================================

/// Cached entry for user details.
struct CachedUser {
    user: User,
    cached_at: Instant,
}

/// Caching wrapper for UserDetailsService.
///
/// Caches loaded users for a configurable duration to reduce database calls.
///
/// # Example
/// ```rust,ignore
/// let cached_service = CachingUserDetailsService::new(my_service)
///     .ttl(Duration::from_secs(300));  // Cache for 5 minutes
/// ```
pub struct CachingUserDetailsService<S>
where
    S: UserDetailsService,
{
    inner: S,
    cache: Arc<RwLock<HashMap<String, CachedUser>>>,
    ttl: Duration,
}

impl<S> CachingUserDetailsService<S>
where
    S: UserDetailsService,
{
    /// Create a new caching service with default TTL (5 minutes).
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(300),
        }
    }

    /// Set the cache TTL (time-to-live).
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Clear the cache.
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Invalidate a specific user from cache.
    pub async fn invalidate(&self, username: &str) {
        let mut cache = self.cache.write().await;
        cache.remove(username);
    }

    /// Check if a cached entry is still valid.
    fn is_valid(&self, entry: &CachedUser) -> bool {
        entry.cached_at.elapsed() < self.ttl
    }
}

#[async_trait]
impl<S> UserDetailsService for CachingUserDetailsService<S>
where
    S: UserDetailsService + Send + Sync,
{
    async fn load_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<User>, UserDetailsError> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(username) {
                if self.is_valid(cached) {
                    return Ok(Some(cached.user.clone()));
                }
            }
        }

        // Load from inner service
        let result = self.inner.load_user_by_username(username).await?;

        // Cache the result if found
        if let Some(ref user) = result {
            let mut cache = self.cache.write().await;
            cache.insert(
                username.to_string(),
                CachedUser {
                    user: user.clone(),
                    cached_at: Instant::now(),
                },
            );
        }

        Ok(result)
    }
}

// =============================================================================
// User Details Authenticator
// =============================================================================

/// Authenticator that uses a UserDetailsService for credential validation.
///
/// # Spring Equivalent
/// Similar to `DaoAuthenticationProvider` in Spring Security.
///
/// # Example
/// ```rust,ignore
/// let authenticator = UserDetailsAuthenticator::new(
///     my_user_details_service,
///     Argon2PasswordEncoder::new(),
/// );
///
/// // Authenticate user
/// let user = authenticator.authenticate("username", "password").await?;
/// ```
#[derive(Clone)]
pub struct UserDetailsAuthenticator<S, E>
where
    S: UserDetailsService + Clone,
    E: PasswordEncoder + Clone,
{
    service: Arc<S>,
    encoder: Arc<E>,
}

impl<S, E> UserDetailsAuthenticator<S, E>
where
    S: UserDetailsService + Clone,
    E: PasswordEncoder + Clone,
{
    /// Create a new authenticator with the given service and encoder.
    pub fn new(service: S, encoder: E) -> Self {
        Self {
            service: Arc::new(service),
            encoder: Arc::new(encoder),
        }
    }

    /// Authenticate a user with username and password.
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<User, UserDetailsError> {
        // Load user
        let user = self
            .service
            .load_user_by_username(username)
            .await?
            .ok_or(UserDetailsError::NotFound)?;

        // Verify password
        if self.encoder.matches(password, user.get_password()) {
            Ok(user)
        } else {
            Err(UserDetailsError::InvalidCredentials)
        }
    }

    /// Get the user details service.
    pub fn service(&self) -> &S {
        &self.service
    }

    /// Get the password encoder.
    pub fn encoder(&self) -> &E {
        &self.encoder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user() -> User {
        User::new("testuser".to_string(), "password".to_string())
            .roles(&["USER".into()])
            .authorities(&["read".into()])
    }

    #[tokio::test]
    async fn test_in_memory_service() {
        let service = InMemoryUserDetailsService::new();
        let user = test_user();

        // Add user
        service.add_user(user.clone()).await;

        // Load user
        let loaded = service.load_user_by_username("testuser").await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().get_username(), "testuser");

        // User exists
        assert!(service.user_exists("testuser").await.unwrap());
        assert!(!service.user_exists("unknown").await.unwrap());
    }

    #[tokio::test]
    async fn test_in_memory_manager() {
        let service = InMemoryUserDetailsService::new();
        let user = test_user();

        // Create user
        service.create_user(&user).await.unwrap();
        assert!(service.user_exists("testuser").await.unwrap());

        // Duplicate create fails
        let result = service.create_user(&user).await;
        assert!(matches!(result, Err(UserDetailsError::AlreadyExists)));

        // Update user
        let updated =
            User::new("testuser".to_string(), "newpass".to_string()).roles(&["ADMIN".into()]);
        service.update_user(&updated).await.unwrap();

        let loaded = service
            .load_user_by_username("testuser")
            .await
            .unwrap()
            .unwrap();
        assert!(loaded.has_role("ADMIN"));

        // Delete user
        service.delete_user("testuser").await.unwrap();
        assert!(!service.user_exists("testuser").await.unwrap());

        // Delete non-existent fails
        let result = service.delete_user("testuser").await;
        assert!(matches!(result, Err(UserDetailsError::NotFound)));
    }

    #[tokio::test]
    async fn test_caching_service() {
        let inner = InMemoryUserDetailsService::new();
        inner.add_user(test_user()).await;

        let cached = CachingUserDetailsService::new(inner).ttl(Duration::from_secs(60));

        // First load (from inner)
        let user1 = cached.load_user_by_username("testuser").await.unwrap();
        assert!(user1.is_some());

        // Second load (from cache)
        let user2 = cached.load_user_by_username("testuser").await.unwrap();
        assert!(user2.is_some());

        // Invalidate cache
        cached.invalidate("testuser").await;

        // Load again (from inner after invalidation)
        let user3 = cached.load_user_by_username("testuser").await.unwrap();
        assert!(user3.is_some());
    }
}
