//! API Key configuration.

/// Where to look for the API key in requests.
#[derive(Debug, Clone)]
pub enum ApiKeyLocation {
    /// Look for the API key in a header (e.g., "X-API-Key").
    Header(String),
    /// Look for the API key in a query parameter (e.g., "?api_key=...").
    Query(String),
    /// Look for the API key in the Authorization header with a custom scheme.
    /// Example: `Authorization: ApiKey sk_live_abc123`
    AuthorizationHeader(String),
}

impl Default for ApiKeyLocation {
    fn default() -> Self {
        Self::Header("X-API-Key".to_string())
    }
}

impl ApiKeyLocation {
    /// Creates a header-based location.
    pub fn header(name: impl Into<String>) -> Self {
        Self::Header(name.into())
    }

    /// Creates a query parameter-based location.
    pub fn query(name: impl Into<String>) -> Self {
        Self::Query(name.into())
    }

    /// Creates an Authorization header-based location with a custom scheme.
    pub fn authorization(scheme: impl Into<String>) -> Self {
        Self::AuthorizationHeader(scheme.into())
    }
}

/// Configuration for API Key authentication.
#[derive(Debug, Clone)]
pub struct ApiKeyConfig {
    /// Locations to look for the API key (checked in order).
    locations: Vec<ApiKeyLocation>,
    /// Whether to validate key expiration.
    validate_expiration: bool,
    /// Whether to check if the key is enabled.
    validate_enabled: bool,
    /// Realm for authentication challenges.
    realm: String,
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            locations: vec![ApiKeyLocation::default()],
            validate_expiration: true,
            validate_enabled: true,
            realm: "API".to_string(),
        }
    }
}

impl ApiKeyConfig {
    /// Creates a new configuration with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a configuration that looks for the API key in a header.
    pub fn header(name: impl Into<String>) -> Self {
        Self {
            locations: vec![ApiKeyLocation::Header(name.into())],
            ..Default::default()
        }
    }

    /// Creates a configuration that looks for the API key in a query parameter.
    pub fn query(name: impl Into<String>) -> Self {
        Self {
            locations: vec![ApiKeyLocation::Query(name.into())],
            ..Default::default()
        }
    }

    /// Creates a configuration that looks for the API key in the Authorization header.
    pub fn authorization(scheme: impl Into<String>) -> Self {
        Self {
            locations: vec![ApiKeyLocation::AuthorizationHeader(scheme.into())],
            ..Default::default()
        }
    }

    /// Adds a location to look for the API key.
    pub fn add_location(mut self, location: ApiKeyLocation) -> Self {
        self.locations.push(location);
        self
    }

    /// Sets the locations to look for the API key.
    pub fn locations(mut self, locations: Vec<ApiKeyLocation>) -> Self {
        self.locations = locations;
        self
    }

    /// Sets whether to validate key expiration.
    pub fn validate_expiration(mut self, validate: bool) -> Self {
        self.validate_expiration = validate;
        self
    }

    /// Sets whether to check if the key is enabled.
    pub fn validate_enabled(mut self, validate: bool) -> Self {
        self.validate_enabled = validate;
        self
    }

    /// Sets the realm for authentication challenges.
    pub fn realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = realm.into();
        self
    }

    /// Returns the locations to check for the API key.
    pub fn get_locations(&self) -> &[ApiKeyLocation] {
        &self.locations
    }

    /// Returns whether to validate key expiration.
    pub fn should_validate_expiration(&self) -> bool {
        self.validate_expiration
    }

    /// Returns whether to validate that keys are enabled.
    pub fn should_validate_enabled(&self) -> bool {
        self.validate_enabled
    }

    /// Returns the realm for authentication challenges.
    pub fn get_realm(&self) -> &str {
        &self.realm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ApiKeyConfig::default();
        assert_eq!(config.get_locations().len(), 1);
        assert!(matches!(
            &config.get_locations()[0],
            ApiKeyLocation::Header(name) if name == "X-API-Key"
        ));
        assert!(config.should_validate_expiration());
        assert!(config.should_validate_enabled());
        assert_eq!(config.get_realm(), "API");
    }

    #[test]
    fn test_header_config() {
        let config = ApiKeyConfig::header("X-Custom-Key");
        assert!(matches!(
            &config.get_locations()[0],
            ApiKeyLocation::Header(name) if name == "X-Custom-Key"
        ));
    }

    #[test]
    fn test_query_config() {
        let config = ApiKeyConfig::query("api_key");
        assert!(matches!(
            &config.get_locations()[0],
            ApiKeyLocation::Query(name) if name == "api_key"
        ));
    }

    #[test]
    fn test_authorization_config() {
        let config = ApiKeyConfig::authorization("ApiKey");
        assert!(matches!(
            &config.get_locations()[0],
            ApiKeyLocation::AuthorizationHeader(scheme) if scheme == "ApiKey"
        ));
    }

    #[test]
    fn test_multiple_locations() {
        let config = ApiKeyConfig::new().locations(vec![
            ApiKeyLocation::header("X-API-Key"),
            ApiKeyLocation::query("api_key"),
            ApiKeyLocation::authorization("Bearer"),
        ]);
        assert_eq!(config.get_locations().len(), 3);
    }

    #[test]
    fn test_add_location() {
        let config =
            ApiKeyConfig::header("X-API-Key").add_location(ApiKeyLocation::query("api_key"));
        assert_eq!(config.get_locations().len(), 2);
    }
}
