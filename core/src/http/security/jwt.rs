//! JWT (JSON Web Token) Authentication.
//!
//! # Spring Security Equivalent
//! Similar to Spring Security's JWT authentication with `JwtAuthenticationToken`.
//!
//! # Features
//! - Token generation and validation
//! - Configurable claims (roles, authorities)
//! - Multiple signing algorithms (HS256, HS384, HS512, RS256, etc.)
//! - Token expiration handling
//!
//! # Example
//! ```rust,ignore
//! use actix_security_core::http::security::jwt::{JwtAuthenticator, JwtConfig};
//!
//! let config = JwtConfig::new("your-secret-key")
//!     .issuer("my-app")
//!     .audience("my-api")
//!     .expiration_hours(24);
//!
//! let authenticator = JwtAuthenticator::new(config);
//! ```

use crate::http::security::config::Authenticator;
use crate::http::security::User;
use actix_web::dev::ServiceRequest;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Re-export Algorithm for convenience
pub use jsonwebtoken::Algorithm;

// =============================================================================
// JWT Claims
// =============================================================================

/// Standard JWT claims with security extensions.
///
/// # Spring Security Equivalent
/// Similar to Spring's `Jwt` claims with custom attributes for roles/authorities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (username)
    pub sub: String,

    /// Issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Audience
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    /// Expiration time (Unix timestamp)
    pub exp: u64,

    /// Issued at (Unix timestamp)
    pub iat: u64,

    /// Not before (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,

    /// JWT ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// User roles
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,

    /// User authorities/permissions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorities: Vec<String>,

    /// Additional custom claims
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub custom: Option<serde_json::Value>,
}

impl Claims {
    /// Create new claims for a user.
    pub fn new(username: &str, expiration_secs: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            sub: username.to_string(),
            iss: None,
            aud: None,
            exp: now + expiration_secs,
            iat: now,
            nbf: None,
            jti: None,
            roles: Vec::new(),
            authorities: Vec::new(),
            custom: None,
        }
    }

    /// Set issuer.
    pub fn issuer(mut self, issuer: &str) -> Self {
        self.iss = Some(issuer.to_string());
        self
    }

    /// Set audience.
    pub fn audience(mut self, audience: &str) -> Self {
        self.aud = Some(audience.to_string());
        self
    }

    /// Set roles.
    pub fn roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    /// Set authorities.
    pub fn authorities(mut self, authorities: Vec<String>) -> Self {
        self.authorities = authorities;
        self
    }

    /// Set custom claims.
    pub fn custom(mut self, custom: serde_json::Value) -> Self {
        self.custom = Some(custom);
        self
    }

    /// Create claims from a User.
    pub fn from_user(user: &User, expiration_secs: u64) -> Self {
        Self::new(user.get_username(), expiration_secs)
            .roles(user.get_roles().to_vec())
            .authorities(user.get_authorities().to_vec())
    }
}

// =============================================================================
// JWT Configuration
// =============================================================================

/// JWT configuration.
///
/// # Example
/// ```rust,ignore
/// let config = JwtConfig::new("my-secret-key")
///     .algorithm(Algorithm::HS512)
///     .issuer("my-app")
///     .audience("my-api")
///     .expiration_hours(24)
///     .leeway_secs(60);
/// ```
#[derive(Clone)]
pub struct JwtConfig {
    /// Secret key for HMAC algorithms or public key for RSA/EC
    secret: String,
    /// Signing algorithm
    algorithm: Algorithm,
    /// Token issuer
    issuer: Option<String>,
    /// Token audience
    audience: Option<String>,
    /// Token expiration in seconds
    expiration_secs: u64,
    /// Leeway for expiration validation (seconds)
    leeway_secs: u64,
    /// Header prefix (default: "Bearer ")
    header_prefix: String,
    /// Header name (default: "Authorization")
    header_name: String,
    /// Validate expiration
    validate_exp: bool,
}

impl JwtConfig {
    /// Create a new JWT configuration with HMAC secret.
    ///
    /// # Arguments
    /// * `secret` - Secret key for signing/verifying tokens (min 32 chars recommended)
    pub fn new(secret: &str) -> Self {
        Self {
            secret: secret.to_string(),
            algorithm: Algorithm::HS256,
            issuer: None,
            audience: None,
            expiration_secs: 3600, // 1 hour default
            leeway_secs: 0,
            header_prefix: "Bearer ".to_string(),
            header_name: "Authorization".to_string(),
            validate_exp: true,
        }
    }

    /// Set the signing algorithm.
    pub fn algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Set the token issuer.
    pub fn issuer(mut self, issuer: &str) -> Self {
        self.issuer = Some(issuer.to_string());
        self
    }

    /// Set the token audience.
    pub fn audience(mut self, audience: &str) -> Self {
        self.audience = Some(audience.to_string());
        self
    }

    /// Set expiration time in seconds.
    pub fn expiration_secs(mut self, secs: u64) -> Self {
        self.expiration_secs = secs;
        self
    }

    /// Set expiration time in hours.
    pub fn expiration_hours(mut self, hours: u64) -> Self {
        self.expiration_secs = hours * 3600;
        self
    }

    /// Set expiration time in days.
    pub fn expiration_days(mut self, days: u64) -> Self {
        self.expiration_secs = days * 86400;
        self
    }

    /// Set leeway for expiration validation.
    pub fn leeway_secs(mut self, secs: u64) -> Self {
        self.leeway_secs = secs;
        self
    }

    /// Set the header prefix (default: "Bearer ").
    pub fn header_prefix(mut self, prefix: &str) -> Self {
        self.header_prefix = prefix.to_string();
        self
    }

    /// Set the header name (default: "Authorization").
    pub fn header_name(mut self, name: &str) -> Self {
        self.header_name = name.to_string();
        self
    }

    /// Disable expiration validation (not recommended for production).
    pub fn disable_exp_validation(mut self) -> Self {
        self.validate_exp = false;
        self
    }

    /// Get expiration duration.
    pub fn expiration_duration(&self) -> Duration {
        Duration::from_secs(self.expiration_secs)
    }
}

// =============================================================================
// JWT Authenticator
// =============================================================================

/// JWT-based authenticator.
///
/// Extracts and validates JWT tokens from the Authorization header.
///
/// # Spring Security Equivalent
/// Similar to `JwtAuthenticationProvider` with `BearerTokenAuthenticationFilter`.
///
/// # Example
/// ```rust,ignore
/// use actix_security_core::http::security::jwt::{JwtAuthenticator, JwtConfig};
///
/// let config = JwtConfig::new("your-256-bit-secret-key-here!")
///     .issuer("my-app")
///     .expiration_hours(24);
///
/// let authenticator = JwtAuthenticator::new(config);
///
/// // Use with SecurityTransform
/// SecurityTransform::new()
///     .config_authenticator(move || authenticator.clone())
///     .config_authorizer(|| /* ... */)
/// ```
#[derive(Clone)]
pub struct JwtAuthenticator {
    config: JwtConfig,
}

impl JwtAuthenticator {
    /// Create a new JWT authenticator.
    pub fn new(config: JwtConfig) -> Self {
        Self { config }
    }

    /// Get the configuration.
    pub fn config(&self) -> &JwtConfig {
        &self.config
    }

    /// Generate a JWT token for a user.
    ///
    /// # Example
    /// ```rust,ignore
    /// let token = authenticator.generate_token(&user)?;
    /// // Returns: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    /// ```
    pub fn generate_token(&self, user: &User) -> Result<String, JwtError> {
        let mut claims = Claims::from_user(user, self.config.expiration_secs);

        if let Some(ref issuer) = self.config.issuer {
            claims = claims.issuer(issuer);
        }
        if let Some(ref audience) = self.config.audience {
            claims = claims.audience(audience);
        }

        let header = Header::new(self.config.algorithm);
        let key = EncodingKey::from_secret(self.config.secret.as_bytes());

        encode(&header, &claims, &key).map_err(JwtError::Encoding)
    }

    /// Generate a token with custom claims.
    pub fn generate_token_with_claims(&self, claims: &Claims) -> Result<String, JwtError> {
        let header = Header::new(self.config.algorithm);
        let key = EncodingKey::from_secret(self.config.secret.as_bytes());

        encode(&header, claims, &key).map_err(JwtError::Encoding)
    }

    /// Validate a token and return the claims.
    pub fn validate_token(&self, token: &str) -> Result<TokenData<Claims>, JwtError> {
        let key = DecodingKey::from_secret(self.config.secret.as_bytes());

        let mut validation = Validation::new(self.config.algorithm);
        validation.leeway = self.config.leeway_secs;
        validation.validate_exp = self.config.validate_exp;

        if let Some(ref issuer) = self.config.issuer {
            validation.set_issuer(&[issuer]);
        }
        if let Some(ref audience) = self.config.audience {
            validation.set_audience(&[audience]);
        }

        decode::<Claims>(token, &key, &validation).map_err(JwtError::Decoding)
    }

    /// Extract token from request header.
    fn extract_token(&self, req: &ServiceRequest) -> Option<String> {
        let header_value = req.headers().get(&self.config.header_name)?;
        let header_str = header_value.to_str().ok()?;

        if header_str.starts_with(&self.config.header_prefix) {
            Some(header_str[self.config.header_prefix.len()..].to_string())
        } else {
            None
        }
    }
}

impl Authenticator for JwtAuthenticator {
    fn get_user(&self, req: &ServiceRequest) -> Option<User> {
        // Extract token from header
        let token = self.extract_token(req)?;

        // Validate token
        let token_data = self.validate_token(&token).ok()?;
        let claims = token_data.claims;

        // Build User from claims
        let roles: Vec<String> = claims.roles;
        let authorities: Vec<String> = claims.authorities;

        Some(
            User::new(claims.sub, String::new())
                .roles(&roles)
                .authorities(&authorities),
        )
    }
}

// =============================================================================
// JWT Error
// =============================================================================

/// JWT-related errors.
#[derive(Debug)]
pub enum JwtError {
    /// Token encoding error
    Encoding(jsonwebtoken::errors::Error),
    /// Token decoding/validation error
    Decoding(jsonwebtoken::errors::Error),
    /// Token expired
    Expired,
    /// Invalid token format
    InvalidFormat,
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::Encoding(e) => write!(f, "JWT encoding error: {}", e),
            JwtError::Decoding(e) => write!(f, "JWT decoding error: {}", e),
            JwtError::Expired => write!(f, "JWT token expired"),
            JwtError::InvalidFormat => write!(f, "Invalid JWT format"),
        }
    }
}

impl std::error::Error for JwtError {}

// =============================================================================
// JWT Token Service (for generating tokens)
// =============================================================================

/// Service for generating and managing JWT tokens.
///
/// # Example
/// ```rust,ignore
/// let token_service = JwtTokenService::new(config);
///
/// // Generate token for user
/// let token = token_service.generate_token(&user)?;
///
/// // Generate refresh token (longer expiration)
/// let refresh_token = token_service.generate_refresh_token(&user)?;
/// ```
#[derive(Clone)]
pub struct JwtTokenService {
    config: JwtConfig,
    refresh_expiration_secs: u64,
}

impl JwtTokenService {
    /// Create a new token service.
    pub fn new(config: JwtConfig) -> Self {
        Self {
            refresh_expiration_secs: config.expiration_secs * 24, // 24x longer for refresh
            config,
        }
    }

    /// Set refresh token expiration.
    pub fn refresh_expiration_days(mut self, days: u64) -> Self {
        self.refresh_expiration_secs = days * 86400;
        self
    }

    /// Generate an access token.
    pub fn generate_token(&self, user: &User) -> Result<String, JwtError> {
        let authenticator = JwtAuthenticator::new(self.config.clone());
        authenticator.generate_token(user)
    }

    /// Generate a refresh token (longer expiration, minimal claims).
    pub fn generate_refresh_token(&self, user: &User) -> Result<String, JwtError> {
        let claims = Claims::new(user.get_username(), self.refresh_expiration_secs);
        let header = Header::new(self.config.algorithm);
        let key = EncodingKey::from_secret(self.config.secret.as_bytes());

        encode(&header, &claims, &key).map_err(JwtError::Encoding)
    }

    /// Validate a token and return claims.
    pub fn validate_token(&self, token: &str) -> Result<Claims, JwtError> {
        let authenticator = JwtAuthenticator::new(self.config.clone());
        authenticator.validate_token(token).map(|td| td.claims)
    }

    /// Get the configuration.
    pub fn config(&self) -> &JwtConfig {
        &self.config
    }
}

// =============================================================================
// Token Pair (Access + Refresh)
// =============================================================================

/// Token pair containing access and refresh tokens.
///
/// # Spring Security Equivalent
/// Similar to OAuth2 token response with access_token and refresh_token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    /// Access token for API authentication
    pub access_token: String,
    /// Refresh token for obtaining new access tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Token type (typically "Bearer")
    pub token_type: String,
    /// Access token expiration in seconds
    pub expires_in: u64,
    /// Refresh token expiration in seconds (if present)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_expires_in: Option<u64>,
}

impl TokenPair {
    /// Create a new token pair.
    pub fn new(access_token: String, expires_in: u64) -> Self {
        Self {
            access_token,
            refresh_token: None,
            token_type: "Bearer".to_string(),
            expires_in,
            refresh_expires_in: None,
        }
    }

    /// Add a refresh token.
    pub fn with_refresh_token(mut self, refresh_token: String, refresh_expires_in: u64) -> Self {
        self.refresh_token = Some(refresh_token);
        self.refresh_expires_in = Some(refresh_expires_in);
        self
    }
}

impl JwtTokenService {
    /// Generate a token pair (access + refresh).
    ///
    /// # Example
    /// ```rust,ignore
    /// let token_pair = token_service.generate_token_pair(&user)?;
    /// println!("Access: {}", token_pair.access_token);
    /// println!("Refresh: {:?}", token_pair.refresh_token);
    /// ```
    pub fn generate_token_pair(&self, user: &User) -> Result<TokenPair, JwtError> {
        let access_token = self.generate_token(user)?;
        let refresh_token = self.generate_refresh_token(user)?;

        Ok(TokenPair::new(access_token, self.config.expiration_secs)
            .with_refresh_token(refresh_token, self.refresh_expiration_secs))
    }

    /// Refresh tokens using a valid refresh token.
    ///
    /// Returns a new token pair if the refresh token is valid.
    pub fn refresh_tokens(&self, refresh_token: &str) -> Result<TokenPair, JwtError> {
        // Validate refresh token
        let claims = self.validate_token(refresh_token)?;

        // Create a minimal user from claims to generate new tokens
        let user = User::new(claims.sub, String::new())
            .roles(&claims.roles)
            .authorities(&claims.authorities);

        // Generate new token pair
        self.generate_token_pair(&user)
    }
}

// =============================================================================
// Claims Extractor Trait
// =============================================================================

/// Trait for extracting user information from JWT claims.
///
/// Implement this trait to customize how users are built from JWT claims.
///
/// # Example
/// ```rust,ignore
/// struct CustomClaimsExtractor;
///
/// impl ClaimsExtractor for CustomClaimsExtractor {
///     fn extract_user(&self, claims: &Claims) -> Option<User> {
///         // Custom extraction logic
///         Some(User::new(claims.sub.clone(), String::new())
///             .roles(&claims.roles))
///     }
/// }
/// ```
pub trait ClaimsExtractor: Send + Sync {
    /// Extract user from JWT claims.
    fn extract_user(&self, claims: &Claims) -> Option<User>;
}

/// Default claims extractor that maps standard claims to User.
#[derive(Clone, Default)]
pub struct DefaultClaimsExtractor {
    /// Claim name for username (default: "sub")
    username_claim: Option<String>,
    /// Claim name for roles (default: "roles")
    roles_claim: Option<String>,
    /// Claim name for authorities (default: "authorities")
    authorities_claim: Option<String>,
}

impl DefaultClaimsExtractor {
    /// Create a new default claims extractor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set custom username claim name.
    pub fn username_claim(mut self, claim: &str) -> Self {
        self.username_claim = Some(claim.to_string());
        self
    }

    /// Set custom roles claim name.
    pub fn roles_claim(mut self, claim: &str) -> Self {
        self.roles_claim = Some(claim.to_string());
        self
    }

    /// Set custom authorities claim name.
    pub fn authorities_claim(mut self, claim: &str) -> Self {
        self.authorities_claim = Some(claim.to_string());
        self
    }
}

impl ClaimsExtractor for DefaultClaimsExtractor {
    fn extract_user(&self, claims: &Claims) -> Option<User> {
        let username = claims.sub.clone();
        let roles = claims.roles.clone();
        let authorities = claims.authorities.clone();

        Some(
            User::new(username, String::new())
                .roles(&roles)
                .authorities(&authorities),
        )
    }
}

// =============================================================================
// RSA Configuration (added to JwtConfig)
// =============================================================================

impl JwtConfig {
    /// Create a JWT configuration for RS256 with PEM-encoded public key.
    ///
    /// Use this for token verification when you only have the public key.
    ///
    /// # Example
    /// ```rust,ignore
    /// let config = JwtConfig::with_rsa_public_key(include_str!("public_key.pem"));
    /// ```
    pub fn with_rsa_public_key(public_key_pem: &str) -> Self {
        Self {
            secret: public_key_pem.to_string(),
            algorithm: Algorithm::RS256,
            issuer: None,
            audience: None,
            expiration_secs: 3600,
            leeway_secs: 0,
            header_prefix: "Bearer ".to_string(),
            header_name: "Authorization".to_string(),
            validate_exp: true,
        }
    }

    /// Check if this config uses RSA algorithm.
    pub fn is_rsa(&self) -> bool {
        matches!(
            self.algorithm,
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512
        )
    }

    /// Check if this config uses HMAC algorithm.
    pub fn is_hmac(&self) -> bool {
        matches!(
            self.algorithm,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        )
    }
}

// Enhanced JwtAuthenticator for RSA support
impl JwtAuthenticator {
    /// Validate token with RSA public key.
    ///
    /// Note: This method works when JwtConfig was created with `with_rsa_public_key`.
    pub fn validate_token_rsa(&self, token: &str) -> Result<TokenData<Claims>, JwtError> {
        if !self.config.is_rsa() {
            return self.validate_token(token);
        }

        let key =
            DecodingKey::from_rsa_pem(self.config.secret.as_bytes()).map_err(JwtError::Decoding)?;

        let mut validation = Validation::new(self.config.algorithm);
        validation.leeway = self.config.leeway_secs;
        validation.validate_exp = self.config.validate_exp;

        if let Some(ref issuer) = self.config.issuer {
            validation.set_issuer(&[issuer]);
        }
        if let Some(ref audience) = self.config.audience {
            validation.set_audience(&[audience]);
        }

        decode::<Claims>(token, &key, &validation).map_err(JwtError::Decoding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user() -> User {
        User::new("testuser".to_string(), "password".to_string())
            .roles(&["USER".into(), "ADMIN".into()])
            .authorities(&["read".into(), "write".into()])
    }

    #[test]
    fn test_generate_and_validate_token() {
        let config = JwtConfig::new("super-secret-key-that-is-long-enough")
            .issuer("test-app")
            .expiration_hours(1);

        let authenticator = JwtAuthenticator::new(config);
        let user = test_user();

        // Generate token
        let token = authenticator.generate_token(&user).unwrap();
        assert!(!token.is_empty());

        // Validate token
        let token_data = authenticator.validate_token(&token).unwrap();
        assert_eq!(token_data.claims.sub, "testuser");
        assert!(token_data.claims.roles.contains(&"USER".to_string()));
        assert!(token_data.claims.roles.contains(&"ADMIN".to_string()));
        assert!(token_data.claims.authorities.contains(&"read".to_string()));
    }

    #[test]
    fn test_invalid_token() {
        let config = JwtConfig::new("super-secret-key-that-is-long-enough");
        let authenticator = JwtAuthenticator::new(config);

        let result = authenticator.validate_token("invalid-token");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_secret() {
        let config1 = JwtConfig::new("secret-key-one-that-is-long-enough");
        let config2 = JwtConfig::new("secret-key-two-that-is-long-enough");

        let auth1 = JwtAuthenticator::new(config1);
        let auth2 = JwtAuthenticator::new(config2);

        let token = auth1.generate_token(&test_user()).unwrap();
        let result = auth2.validate_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_claims_from_user() {
        let user = test_user();
        let claims = Claims::from_user(&user, 3600);

        assert_eq!(claims.sub, "testuser");
        assert!(claims.roles.contains(&"USER".to_string()));
        assert!(claims.authorities.contains(&"read".to_string()));
    }

    #[test]
    fn test_token_service() {
        let config = JwtConfig::new("super-secret-key-that-is-long-enough").expiration_hours(1);

        let service = JwtTokenService::new(config).refresh_expiration_days(7);
        let user = test_user();

        let access_token = service.generate_token(&user).unwrap();
        let refresh_token = service.generate_refresh_token(&user).unwrap();

        assert!(!access_token.is_empty());
        assert!(!refresh_token.is_empty());
        assert_ne!(access_token, refresh_token);

        // Validate access token has roles
        let claims = service.validate_token(&access_token).unwrap();
        assert!(!claims.roles.is_empty());

        // Validate refresh token has no roles
        let refresh_claims = service.validate_token(&refresh_token).unwrap();
        assert!(refresh_claims.roles.is_empty());
    }
}
