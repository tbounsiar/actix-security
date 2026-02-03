//! API Key authenticator implementation.

use super::config::{ApiKeyConfig, ApiKeyLocation};
use super::error::ApiKeyError;
use super::repository::ApiKeyRepository;
use crate::http::security::{Authenticator, User};
use actix_web::dev::ServiceRequest;
use std::sync::Arc;

/// Authenticator that validates API keys from requests.
///
/// This authenticator extracts API keys from configured locations (header, query parameter,
/// or Authorization header) and validates them against a repository.
///
/// # Example
///
/// ```ignore
/// use actix_security::http::security::api_key::{
///     ApiKeyAuthenticator, ApiKeyConfig, ApiKey, InMemoryApiKeyRepository,
/// };
///
/// let repository = InMemoryApiKeyRepository::new()
///     .with_key(ApiKey::new("sk_live_abc123")
///         .roles(vec!["API_USER".into()])
///         .authorities(vec!["api:read".into()]));
///
/// let authenticator = ApiKeyAuthenticator::new(repository)
///     .config(ApiKeyConfig::header("X-API-Key"));
/// ```
pub struct ApiKeyAuthenticator<R: ApiKeyRepository> {
    repository: Arc<R>,
    config: ApiKeyConfig,
}

impl<R: ApiKeyRepository> ApiKeyAuthenticator<R> {
    /// Creates a new API key authenticator with the given repository.
    pub fn new(repository: R) -> Self {
        Self {
            repository: Arc::new(repository),
            config: ApiKeyConfig::default(),
        }
    }

    /// Creates a new API key authenticator with a shared repository.
    pub fn with_shared_repository(repository: Arc<R>) -> Self {
        Self {
            repository,
            config: ApiKeyConfig::default(),
        }
    }

    /// Sets the configuration for this authenticator.
    pub fn config(mut self, config: ApiKeyConfig) -> Self {
        self.config = config;
        self
    }

    /// Extracts the API key from the request based on configured locations.
    fn extract_key(&self, req: &ServiceRequest) -> Option<String> {
        for location in self.config.get_locations() {
            if let Some(key) = self.extract_from_location(req, location) {
                return Some(key);
            }
        }
        None
    }

    /// Extracts the API key from a specific location.
    fn extract_from_location(
        &self,
        req: &ServiceRequest,
        location: &ApiKeyLocation,
    ) -> Option<String> {
        match location {
            ApiKeyLocation::Header(name) => req
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            ApiKeyLocation::Query(name) => req.query_string().split('&').find_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                if key == name {
                    Some(urlencoding::decode(value).ok()?.into_owned())
                } else {
                    None
                }
            }),
            ApiKeyLocation::AuthorizationHeader(scheme) => req
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|auth| {
                    let (auth_scheme, token) = auth.split_once(' ')?;
                    if auth_scheme.eq_ignore_ascii_case(scheme) {
                        Some(token.to_string())
                    } else {
                        None
                    }
                }),
        }
    }

    /// Validates an API key and returns a User if valid.
    fn validate_key(&self, key_value: &str) -> Result<User, ApiKeyError> {
        let api_key = self
            .repository
            .find_by_key(key_value)
            .ok_or(ApiKeyError::Invalid)?;

        // Check if key is enabled
        if self.config.should_validate_enabled() && !api_key.is_enabled() {
            return Err(ApiKeyError::Disabled);
        }

        // Check if key has expired
        if self.config.should_validate_expiration() && api_key.is_expired() {
            return Err(ApiKeyError::Expired);
        }

        // Convert API key to User
        let mut user = User::new(
            api_key.get_name().unwrap_or(api_key.get_key()).to_string(),
            String::new(), // No password for API keys
        );

        // Add roles
        for role in api_key.get_roles() {
            user = user.roles(std::slice::from_ref(role));
        }

        // Add authorities
        for authority in api_key.get_authorities() {
            user = user.authorities(std::slice::from_ref(authority));
        }

        Ok(user)
    }
}

impl<R: ApiKeyRepository + 'static> Authenticator for ApiKeyAuthenticator<R> {
    fn get_user(&self, req: &ServiceRequest) -> Option<User> {
        let key_value = self.extract_key(req)?;
        self.validate_key(&key_value).ok()
    }
}

impl<R: ApiKeyRepository> Clone for ApiKeyAuthenticator<R> {
    fn clone(&self) -> Self {
        Self {
            repository: Arc::clone(&self.repository),
            config: self.config.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::key::ApiKey;
    use super::super::repository::InMemoryApiKeyRepository;
    use super::*;
    use actix_web::test::TestRequest;
    use std::time::SystemTime;

    fn create_test_repository() -> InMemoryApiKeyRepository {
        InMemoryApiKeyRepository::new()
            .with_key(
                ApiKey::new("valid_key")
                    .name("Test Key")
                    .roles(vec!["API_USER".into()])
                    .authorities(vec!["api:read".into()]),
            )
            .with_key(
                ApiKey::new("disabled_key")
                    .name("Disabled Key")
                    .enabled(false),
            )
            .with_key(
                ApiKey::new("expired_key")
                    .name("Expired Key")
                    .expires_at(SystemTime::UNIX_EPOCH),
            )
    }

    #[test]
    fn test_extract_from_header() {
        let repo = create_test_repository();
        let auth = ApiKeyAuthenticator::new(repo).config(ApiKeyConfig::header("X-API-Key"));

        let req = TestRequest::default()
            .insert_header(("X-API-Key", "valid_key"))
            .to_srv_request();

        let user = auth.get_user(&req);
        assert!(user.is_some());
        assert_eq!(user.unwrap().get_username(), "Test Key");
    }

    #[test]
    fn test_extract_from_query() {
        let repo = create_test_repository();
        let auth = ApiKeyAuthenticator::new(repo).config(ApiKeyConfig::query("api_key"));

        let req = TestRequest::with_uri("/?api_key=valid_key").to_srv_request();

        let user = auth.get_user(&req);
        assert!(user.is_some());
    }

    #[test]
    fn test_extract_from_authorization_header() {
        let repo = create_test_repository();
        let auth = ApiKeyAuthenticator::new(repo).config(ApiKeyConfig::authorization("ApiKey"));

        let req = TestRequest::default()
            .insert_header(("Authorization", "ApiKey valid_key"))
            .to_srv_request();

        let user = auth.get_user(&req);
        assert!(user.is_some());
    }

    #[test]
    fn test_invalid_key() {
        let repo = create_test_repository();
        let auth = ApiKeyAuthenticator::new(repo);

        let req = TestRequest::default()
            .insert_header(("X-API-Key", "invalid_key"))
            .to_srv_request();

        let user = auth.get_user(&req);
        assert!(user.is_none());
    }

    #[test]
    fn test_disabled_key() {
        let repo = create_test_repository();
        let auth = ApiKeyAuthenticator::new(repo);

        let req = TestRequest::default()
            .insert_header(("X-API-Key", "disabled_key"))
            .to_srv_request();

        let user = auth.get_user(&req);
        assert!(user.is_none());
    }

    #[test]
    fn test_expired_key() {
        let repo = create_test_repository();
        let auth = ApiKeyAuthenticator::new(repo);

        let req = TestRequest::default()
            .insert_header(("X-API-Key", "expired_key"))
            .to_srv_request();

        let user = auth.get_user(&req);
        assert!(user.is_none());
    }

    #[test]
    fn test_missing_key() {
        let repo = create_test_repository();
        let auth = ApiKeyAuthenticator::new(repo);

        let req = TestRequest::default().to_srv_request();

        let user = auth.get_user(&req);
        assert!(user.is_none());
    }

    #[test]
    fn test_multiple_locations() {
        let repo = create_test_repository();
        let auth = ApiKeyAuthenticator::new(repo).config(ApiKeyConfig::new().locations(vec![
            ApiKeyLocation::header("X-API-Key"),
            ApiKeyLocation::query("api_key"),
        ]));

        // Test header
        let req = TestRequest::default()
            .insert_header(("X-API-Key", "valid_key"))
            .to_srv_request();
        assert!(auth.get_user(&req).is_some());

        // Test query
        let req = TestRequest::with_uri("/?api_key=valid_key").to_srv_request();
        assert!(auth.get_user(&req).is_some());
    }

    #[test]
    fn test_user_has_roles_and_authorities() {
        let repo = InMemoryApiKeyRepository::new().with_key(
            ApiKey::new("full_key")
                .name("Full Key")
                .roles(vec!["ADMIN".into(), "USER".into()])
                .authorities(vec!["api:read".into(), "api:write".into()]),
        );

        let auth = ApiKeyAuthenticator::new(repo);

        let req = TestRequest::default()
            .insert_header(("X-API-Key", "full_key"))
            .to_srv_request();

        let user = auth.get_user(&req).unwrap();
        assert!(user.has_role("ADMIN"));
        assert!(user.has_role("USER"));
        assert!(user.has_authority("api:read"));
        assert!(user.has_authority("api:write"));
    }

    #[test]
    fn test_skip_expiration_validation() {
        let repo = create_test_repository();
        let auth = ApiKeyAuthenticator::new(repo)
            .config(ApiKeyConfig::default().validate_expiration(false));

        let req = TestRequest::default()
            .insert_header(("X-API-Key", "expired_key"))
            .to_srv_request();

        // Should succeed because expiration validation is disabled
        let user = auth.get_user(&req);
        assert!(user.is_some());
    }

    #[test]
    fn test_skip_enabled_validation() {
        let repo = create_test_repository();
        let auth =
            ApiKeyAuthenticator::new(repo).config(ApiKeyConfig::default().validate_enabled(false));

        let req = TestRequest::default()
            .insert_header(("X-API-Key", "disabled_key"))
            .to_srv_request();

        // Should succeed because enabled validation is disabled
        let user = auth.get_user(&req);
        assert!(user.is_some());
    }

    #[test]
    fn test_url_encoded_query_param() {
        let repo = InMemoryApiKeyRepository::new().with_key(ApiKey::new("key+with+spaces"));

        let auth = ApiKeyAuthenticator::new(repo).config(ApiKeyConfig::query("api_key"));

        let req = TestRequest::with_uri("/?api_key=key%2Bwith%2Bspaces").to_srv_request();

        let user = auth.get_user(&req);
        assert!(user.is_some());
    }
}
