//! API Key Authentication for Actix Web.
//!
//! # Overview
//!
//! API Key authentication is a simple authentication method where clients
//! include a pre-shared key in their requests. It's commonly used for:
//! - Service-to-service communication
//! - Public APIs with usage tracking
//! - Simple authentication without user sessions
//!
//! # Key Locations
//!
//! API keys can be extracted from:
//! - **Header** (recommended): `X-API-Key: your-api-key`
//! - **Authorization header**: `Authorization: ApiKey your-api-key`
//! - **Query parameter**: `?api_key=your-api-key` (less secure)
//!
//! # Usage
//!
//! ## Basic Setup
//!
//! ```ignore
//! use actix_security::http::security::api_key::{
//!     ApiKeyAuthenticator, InMemoryApiKeyRepository, ApiKeyConfig, ApiKey,
//! };
//!
//! // Create API key repository
//! let mut repository = InMemoryApiKeyRepository::new();
//!
//! // Add API keys
//! repository.add_key(ApiKey::new("sk_live_abc123")
//!     .name("Production Key")
//!     .roles(vec!["API_USER".into()])
//!     .authorities(vec!["api:read".into(), "api:write".into()]));
//!
//! // Create authenticator
//! let authenticator = ApiKeyAuthenticator::new(repository);
//! ```
//!
//! ## With Custom Header
//!
//! ```ignore
//! let config = ApiKeyConfig::header("Authorization")
//!     .prefix("ApiKey ");  // Expects: Authorization: ApiKey sk_xxx
//!
//! let authenticator = ApiKeyAuthenticator::with_config(repository, config);
//! ```
//!
//! ## Multiple Locations
//!
//! ```ignore
//! let config = ApiKeyConfig::new()
//!     .header("X-API-Key")
//!     .query_param("api_key")
//!     .authorization_scheme("ApiKey");
//!
//! let authenticator = ApiKeyAuthenticator::with_config(repository, config);
//! ```
//!
//! # Spring Security Comparison
//!
//! | Spring Security | Actix Security |
//! |-----------------|----------------|
//! | Custom `AuthenticationFilter` | `ApiKeyAuthenticator` |
//! | `AuthenticationProvider` | `ApiKeyRepository` |
//! | `AbstractPreAuthenticatedProcessingFilter` | `ApiKeyConfig` locations |
//!
//! # Security Considerations
//!
//! 1. **Use HTTPS** - API keys are transmitted in plaintext
//! 2. **Rotate keys** - Implement key rotation policies
//! 3. **Limit scope** - Use authorities to restrict key capabilities
//! 4. **Rate limit** - Prevent abuse with rate limiting per key
//! 5. **Audit** - Log API key usage for security monitoring
//!
//! # Example with Middleware
//!
//! ```ignore
//! use actix_security::http::security::{
//!     SecurityTransform, AuthenticationManager,
//!     api_key::{ApiKeyAuthenticator, InMemoryApiKeyRepository, ApiKey},
//! };
//!
//! let mut repository = InMemoryApiKeyRepository::new();
//! repository.add_key(ApiKey::new("sk_test_123").roles(vec!["USER".into()]));
//!
//! let authenticator = ApiKeyAuthenticator::new(repository);
//!
//! App::new()
//!     .wrap(SecurityTransform::new()
//!         .config_authenticator(move || authenticator.clone()))
//!     .service(my_api_endpoint)
//! ```

mod authenticator;
mod config;
mod error;
mod key;
mod repository;

pub use authenticator::ApiKeyAuthenticator;
pub use config::{ApiKeyConfig, ApiKeyLocation};
pub use error::ApiKeyError;
pub use key::{ApiKey, ApiKeyBuilder};
pub use repository::{ApiKeyRepository, InMemoryApiKeyRepository};
