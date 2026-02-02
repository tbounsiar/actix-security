//! OAuth2 and OpenID Connect (OIDC) Authentication
//!
//! This module provides OAuth2 2.0 and OpenID Connect authentication support,
//! similar to Spring Security's OAuth2 Login.
//!
//! # Features
//!
//! - **Authorization Code Flow** - Standard OAuth2 flow for web applications
//! - **PKCE Support** - Proof Key for Code Exchange for enhanced security
//! - **OIDC Discovery** - Automatic provider configuration via well-known endpoints
//! - **Multiple Providers** - Built-in support for Google, GitHub, Microsoft, etc.
//! - **Custom Providers** - Easy to add custom OAuth2/OIDC providers
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use actix_security_core::http::security::oauth2::{
//!     OAuth2Config, OAuth2Provider, OAuth2Client
//! };
//!
//! // Configure Google OAuth2
//! let config = OAuth2Config::new(
//!     "your-client-id",
//!     "your-client-secret",
//!     "http://localhost:8080/oauth2/callback/google"
//! )
//! .provider(OAuth2Provider::Google)
//! .scopes(vec!["openid", "email", "profile"]);
//!
//! let client = OAuth2Client::new(config).await?;
//!
//! // Generate authorization URL
//! let (auth_url, csrf_token, nonce) = client.authorization_url();
//! ```
//!
//! # Spring Security Comparison
//!
//! | Spring Security | Actix Security |
//! |-----------------|----------------|
//! | `ClientRegistration` | `OAuth2Config` |
//! | `ClientRegistrationRepository` | `OAuth2ClientRepository` |
//! | `OAuth2AuthorizedClient` | `OAuth2Client` |
//! | `OAuth2User` | `OAuth2User` |
//! | `OidcUser` | `OidcUser` |

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use actix_web::dev::ServiceRequest;
use actix_web::http::header::AUTHORIZATION;
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    ClientId as OidcClientId, ClientSecret as OidcClientSecret, IssuerUrl, Nonce,
    RedirectUrl as OidcRedirectUrl, TokenResponse as OidcTokenResponse,
};
use serde::{Deserialize, Serialize};
use url::Url;

use super::config::Authenticator;
use super::user::User;

/// OAuth2 error types
#[derive(Debug, Clone)]
pub enum OAuth2Error {
    /// Configuration error
    Configuration(String),
    /// Provider discovery failed
    Discovery(String),
    /// Token exchange failed
    TokenExchange(String),
    /// Token validation failed
    TokenValidation(String),
    /// User info retrieval failed
    UserInfo(String),
    /// Invalid state/CSRF token
    InvalidState(String),
    /// Invalid nonce
    InvalidNonce(String),
}

impl fmt::Display for OAuth2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OAuth2Error::Configuration(msg) => write!(f, "Configuration error: {}", msg),
            OAuth2Error::Discovery(msg) => write!(f, "Discovery error: {}", msg),
            OAuth2Error::TokenExchange(msg) => write!(f, "Token exchange error: {}", msg),
            OAuth2Error::TokenValidation(msg) => write!(f, "Token validation error: {}", msg),
            OAuth2Error::UserInfo(msg) => write!(f, "User info error: {}", msg),
            OAuth2Error::InvalidState(msg) => write!(f, "Invalid state: {}", msg),
            OAuth2Error::InvalidNonce(msg) => write!(f, "Invalid nonce: {}", msg),
        }
    }
}

impl std::error::Error for OAuth2Error {}

/// Common OAuth2/OIDC providers with pre-configured endpoints
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OAuth2Provider {
    /// Google OAuth2/OIDC
    Google,
    /// GitHub OAuth2
    GitHub,
    /// Microsoft/Azure AD OAuth2/OIDC
    Microsoft,
    /// Facebook OAuth2
    Facebook,
    /// Apple Sign In
    Apple,
    /// Okta OIDC
    Okta,
    /// Auth0 OIDC
    Auth0,
    /// Keycloak OIDC
    Keycloak,
    /// Custom provider (requires manual configuration)
    Custom,
}

impl OAuth2Provider {
    /// Get the OIDC discovery URL for this provider
    pub fn discovery_url(&self) -> Option<&'static str> {
        match self {
            OAuth2Provider::Google => {
                Some("https://accounts.google.com/.well-known/openid-configuration")
            }
            OAuth2Provider::Microsoft => Some(
                "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
            ),
            OAuth2Provider::Apple => {
                Some("https://appleid.apple.com/.well-known/openid-configuration")
            }
            _ => None,
        }
    }

    /// Get the authorization endpoint for this provider
    pub fn auth_url(&self) -> Option<&'static str> {
        match self {
            OAuth2Provider::Google => Some("https://accounts.google.com/o/oauth2/v2/auth"),
            OAuth2Provider::GitHub => Some("https://github.com/login/oauth/authorize"),
            OAuth2Provider::Microsoft => {
                Some("https://login.microsoftonline.com/common/oauth2/v2.0/authorize")
            }
            OAuth2Provider::Facebook => Some("https://www.facebook.com/v18.0/dialog/oauth"),
            OAuth2Provider::Apple => Some("https://appleid.apple.com/auth/authorize"),
            _ => None,
        }
    }

    /// Get the token endpoint for this provider
    pub fn token_url(&self) -> Option<&'static str> {
        match self {
            OAuth2Provider::Google => Some("https://oauth2.googleapis.com/token"),
            OAuth2Provider::GitHub => Some("https://github.com/login/oauth/access_token"),
            OAuth2Provider::Microsoft => {
                Some("https://login.microsoftonline.com/common/oauth2/v2.0/token")
            }
            OAuth2Provider::Facebook => Some("https://graph.facebook.com/v18.0/oauth/access_token"),
            OAuth2Provider::Apple => Some("https://appleid.apple.com/auth/token"),
            _ => None,
        }
    }

    /// Get the user info endpoint for this provider
    pub fn userinfo_url(&self) -> Option<&'static str> {
        match self {
            OAuth2Provider::Google => Some("https://openidconnect.googleapis.com/v1/userinfo"),
            OAuth2Provider::GitHub => Some("https://api.github.com/user"),
            OAuth2Provider::Microsoft => Some("https://graph.microsoft.com/oidc/userinfo"),
            OAuth2Provider::Facebook => Some("https://graph.facebook.com/me?fields=id,name,email"),
            _ => None,
        }
    }

    /// Get default scopes for this provider
    pub fn default_scopes(&self) -> Vec<&'static str> {
        match self {
            OAuth2Provider::Google => vec!["openid", "email", "profile"],
            OAuth2Provider::GitHub => vec!["read:user", "user:email"],
            OAuth2Provider::Microsoft => vec!["openid", "email", "profile"],
            OAuth2Provider::Facebook => vec!["email", "public_profile"],
            OAuth2Provider::Apple => vec!["openid", "email", "name"],
            OAuth2Provider::Okta => vec!["openid", "email", "profile"],
            OAuth2Provider::Auth0 => vec!["openid", "email", "profile"],
            OAuth2Provider::Keycloak => vec!["openid", "email", "profile"],
            OAuth2Provider::Custom => vec!["openid"],
        }
    }

    /// Check if this provider supports OIDC
    pub fn supports_oidc(&self) -> bool {
        matches!(
            self,
            OAuth2Provider::Google
                | OAuth2Provider::Microsoft
                | OAuth2Provider::Apple
                | OAuth2Provider::Okta
                | OAuth2Provider::Auth0
                | OAuth2Provider::Keycloak
        )
    }
}

/// OAuth2 configuration for a client registration
///
/// Similar to Spring Security's `ClientRegistration`.
///
/// # Example
///
/// ```rust,ignore
/// let config = OAuth2Config::new(
///     "client-id",
///     "client-secret",
///     "http://localhost:8080/oauth2/callback/google"
/// )
/// .provider(OAuth2Provider::Google)
/// .scopes(vec!["openid", "email", "profile"]);
/// ```
#[derive(Debug, Clone)]
pub struct OAuth2Config {
    /// Registration ID (e.g., "google", "github")
    pub registration_id: String,
    /// OAuth2 client ID
    pub client_id: String,
    /// OAuth2 client secret
    pub client_secret: String,
    /// Redirect URI for callbacks
    pub redirect_uri: String,
    /// OAuth2 provider
    pub provider: OAuth2Provider,
    /// Authorization endpoint URL (optional, auto-discovered for OIDC)
    pub authorization_uri: Option<String>,
    /// Token endpoint URL (optional, auto-discovered for OIDC)
    pub token_uri: Option<String>,
    /// User info endpoint URL (optional, auto-discovered for OIDC)
    pub userinfo_uri: Option<String>,
    /// OIDC issuer URL (for discovery)
    pub issuer_uri: Option<String>,
    /// JWK Set URI (for ID token validation)
    pub jwk_set_uri: Option<String>,
    /// OAuth2 scopes
    pub scopes: Vec<String>,
    /// Use PKCE (Proof Key for Code Exchange)
    pub use_pkce: bool,
    /// Custom parameters for authorization request
    pub authorization_params: HashMap<String, String>,
    /// Attribute name for username extraction
    pub username_attribute: String,
}

impl OAuth2Config {
    /// Create a new OAuth2 configuration
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth2 client ID
    /// * `client_secret` - The OAuth2 client secret
    /// * `redirect_uri` - The callback URL for authorization response
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            registration_id: String::new(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            provider: OAuth2Provider::Custom,
            authorization_uri: None,
            token_uri: None,
            userinfo_uri: None,
            issuer_uri: None,
            jwk_set_uri: None,
            scopes: vec!["openid".to_string()],
            use_pkce: true,
            authorization_params: HashMap::new(),
            username_attribute: "sub".to_string(),
        }
    }

    /// Set the registration ID
    pub fn registration_id(mut self, id: impl Into<String>) -> Self {
        self.registration_id = id.into();
        self
    }

    /// Set the OAuth2 provider
    ///
    /// This will auto-configure endpoints for known providers.
    pub fn provider(mut self, provider: OAuth2Provider) -> Self {
        self.provider = provider;
        if self.registration_id.is_empty() {
            self.registration_id = format!("{:?}", provider).to_lowercase();
        }

        // Set default endpoints from provider
        if let Some(auth_url) = provider.auth_url() {
            self.authorization_uri = Some(auth_url.to_string());
        }
        if let Some(token_url) = provider.token_url() {
            self.token_uri = Some(token_url.to_string());
        }
        if let Some(userinfo_url) = provider.userinfo_url() {
            self.userinfo_uri = Some(userinfo_url.to_string());
        }

        // Set default scopes
        if self.scopes.len() == 1 && self.scopes[0] == "openid" {
            self.scopes = provider
                .default_scopes()
                .into_iter()
                .map(String::from)
                .collect();
        }

        // GitHub doesn't support PKCE
        if matches!(provider, OAuth2Provider::GitHub | OAuth2Provider::Facebook) {
            self.use_pkce = false;
        }

        self
    }

    /// Set the authorization endpoint URL
    pub fn authorization_uri(mut self, uri: impl Into<String>) -> Self {
        self.authorization_uri = Some(uri.into());
        self
    }

    /// Set the token endpoint URL
    pub fn token_uri(mut self, uri: impl Into<String>) -> Self {
        self.token_uri = Some(uri.into());
        self
    }

    /// Set the user info endpoint URL
    pub fn userinfo_uri(mut self, uri: impl Into<String>) -> Self {
        self.userinfo_uri = Some(uri.into());
        self
    }

    /// Set the OIDC issuer URL for auto-discovery
    pub fn issuer_uri(mut self, uri: impl Into<String>) -> Self {
        self.issuer_uri = Some(uri.into());
        self
    }

    /// Set the JWK Set URI for ID token validation
    pub fn jwk_set_uri(mut self, uri: impl Into<String>) -> Self {
        self.jwk_set_uri = Some(uri.into());
        self
    }

    /// Set the OAuth2 scopes
    pub fn scopes(mut self, scopes: Vec<impl Into<String>>) -> Self {
        self.scopes = scopes.into_iter().map(|s| s.into()).collect();
        self
    }

    /// Add a scope
    pub fn add_scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    /// Enable or disable PKCE
    pub fn use_pkce(mut self, use_pkce: bool) -> Self {
        self.use_pkce = use_pkce;
        self
    }

    /// Add a custom authorization parameter
    pub fn authorization_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.authorization_params.insert(key.into(), value.into());
        self
    }

    /// Set the attribute name used for extracting the username
    pub fn username_attribute(mut self, attr: impl Into<String>) -> Self {
        self.username_attribute = attr.into();
        self
    }
}

/// User information retrieved from OAuth2 provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2User {
    /// User's unique identifier (subject)
    pub sub: String,
    /// User's name
    pub name: Option<String>,
    /// User's given name
    pub given_name: Option<String>,
    /// User's family name
    pub family_name: Option<String>,
    /// User's email
    pub email: Option<String>,
    /// Whether email is verified
    pub email_verified: Option<bool>,
    /// User's picture URL
    pub picture: Option<String>,
    /// User's locale
    pub locale: Option<String>,
    /// Provider-specific attributes
    #[serde(flatten)]
    pub attributes: HashMap<String, serde_json::Value>,
    /// OAuth2 access token
    #[serde(skip)]
    pub access_token: Option<String>,
    /// OAuth2 refresh token
    #[serde(skip)]
    pub refresh_token: Option<String>,
    /// Token expiration time (Unix timestamp)
    pub expires_at: Option<i64>,
    /// Provider that authenticated this user
    pub provider: String,
}

impl OAuth2User {
    /// Create a new OAuth2User with minimal information
    pub fn new(sub: impl Into<String>, provider: impl Into<String>) -> Self {
        Self {
            sub: sub.into(),
            name: None,
            given_name: None,
            family_name: None,
            email: None,
            email_verified: None,
            picture: None,
            locale: None,
            attributes: HashMap::new(),
            access_token: None,
            refresh_token: None,
            expires_at: None,
            provider: provider.into(),
        }
    }

    /// Get a specific attribute value
    pub fn get_attribute(&self, key: &str) -> Option<&serde_json::Value> {
        self.attributes.get(key)
    }

    /// Get the username (tries email first, then sub)
    pub fn username(&self) -> &str {
        self.email.as_deref().unwrap_or(&self.sub)
    }

    /// Convert to a User for authentication
    pub fn to_user(&self) -> User {
        User::new(self.username().to_string(), String::new())
            .roles(&["USER".to_string()])
            .authorities(&[format!("OAUTH2_USER_{}", self.provider.to_uppercase())])
    }
}

/// OIDC user with ID token claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcUser {
    /// Base OAuth2 user info
    #[serde(flatten)]
    pub oauth2_user: OAuth2User,
    /// ID token claims
    pub id_token_claims: Option<IdTokenClaims>,
    /// Raw ID token (JWT)
    #[serde(skip)]
    pub id_token: Option<String>,
}

/// ID Token claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer
    pub iss: String,
    /// Subject
    pub sub: String,
    /// Audience
    pub aud: Vec<String>,
    /// Expiration time
    pub exp: i64,
    /// Issued at time
    pub iat: i64,
    /// Authentication time
    pub auth_time: Option<i64>,
    /// Nonce
    pub nonce: Option<String>,
    /// Access token hash
    pub at_hash: Option<String>,
}

impl OidcUser {
    /// Convert to a User for authentication
    pub fn to_user(&self) -> User {
        self.oauth2_user.to_user()
    }
}

/// Authorization request state (stored in session)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequestState {
    /// CSRF state token
    pub state: String,
    /// PKCE code verifier (if PKCE is used)
    pub pkce_verifier: Option<String>,
    /// OIDC nonce (if OIDC is used)
    pub nonce: Option<String>,
    /// Redirect URL after successful authentication
    pub redirect_uri: Option<String>,
    /// Provider registration ID
    pub registration_id: String,
    /// Timestamp when the request was created
    pub created_at: i64,
}

/// OAuth2 client for handling authorization flows
///
/// Similar to Spring Security's `OAuth2AuthorizedClientService`.
#[derive(Clone)]
pub struct OAuth2Client {
    config: OAuth2Config,
    oauth2_client: BasicClient,
    oidc_client: Option<Arc<CoreClient>>,
}

impl OAuth2Client {
    /// Create a new OAuth2 client from configuration
    ///
    /// For OIDC providers, this will perform discovery to fetch provider metadata.
    pub async fn new(config: OAuth2Config) -> Result<Self, OAuth2Error> {
        // Build the basic OAuth2 client
        let auth_url = config
            .authorization_uri
            .as_ref()
            .ok_or_else(|| OAuth2Error::Configuration("Missing authorization URI".to_string()))?;

        let token_url = config
            .token_uri
            .as_ref()
            .ok_or_else(|| OAuth2Error::Configuration("Missing token URI".to_string()))?;

        let oauth2_client = BasicClient::new(
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
            AuthUrl::new(auth_url.clone())
                .map_err(|e| OAuth2Error::Configuration(e.to_string()))?,
            Some(
                TokenUrl::new(token_url.clone())
                    .map_err(|e| OAuth2Error::Configuration(e.to_string()))?,
            ),
        )
        .set_redirect_uri(
            RedirectUrl::new(config.redirect_uri.clone())
                .map_err(|e| OAuth2Error::Configuration(e.to_string()))?,
        );

        // For OIDC providers, try to create an OIDC client
        let oidc_client = if config.provider.supports_oidc() {
            if let Some(issuer_uri) = &config.issuer_uri {
                match Self::create_oidc_client(&config, issuer_uri).await {
                    Ok(client) => Some(Arc::new(client)),
                    Err(e) => {
                        // Log warning but continue without OIDC
                        eprintln!("Warning: OIDC discovery failed: {}", e);
                        None
                    }
                }
            } else if let Some(discovery_url) = config.provider.discovery_url() {
                // Extract issuer from discovery URL
                let issuer = discovery_url.trim_end_matches("/.well-known/openid-configuration");
                match Self::create_oidc_client(&config, issuer).await {
                    Ok(client) => Some(Arc::new(client)),
                    Err(e) => {
                        eprintln!("Warning: OIDC discovery failed: {}", e);
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            config,
            oauth2_client,
            oidc_client,
        })
    }

    /// Create a new OAuth2 client without OIDC discovery (sync)
    ///
    /// Use this when you don't need OIDC features or want to avoid async initialization.
    pub fn new_basic(config: OAuth2Config) -> Result<Self, OAuth2Error> {
        let auth_url = config
            .authorization_uri
            .as_ref()
            .ok_or_else(|| OAuth2Error::Configuration("Missing authorization URI".to_string()))?;

        let token_url = config
            .token_uri
            .as_ref()
            .ok_or_else(|| OAuth2Error::Configuration("Missing token URI".to_string()))?;

        let oauth2_client = BasicClient::new(
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
            AuthUrl::new(auth_url.clone())
                .map_err(|e| OAuth2Error::Configuration(e.to_string()))?,
            Some(
                TokenUrl::new(token_url.clone())
                    .map_err(|e| OAuth2Error::Configuration(e.to_string()))?,
            ),
        )
        .set_redirect_uri(
            RedirectUrl::new(config.redirect_uri.clone())
                .map_err(|e| OAuth2Error::Configuration(e.to_string()))?,
        );

        Ok(Self {
            config,
            oauth2_client,
            oidc_client: None,
        })
    }

    /// Create an OIDC client with discovery
    async fn create_oidc_client(
        config: &OAuth2Config,
        issuer_uri: &str,
    ) -> Result<CoreClient, OAuth2Error> {
        let issuer_url = IssuerUrl::new(issuer_uri.to_string())
            .map_err(|e| OAuth2Error::Configuration(e.to_string()))?;

        // Discover provider metadata using openidconnect's async http client
        let provider_metadata = CoreProviderMetadata::discover_async(
            issuer_url,
            openidconnect::reqwest::async_http_client,
        )
        .await
        .map_err(|e| OAuth2Error::Discovery(format!("{:?}", e)))?;

        // Build OIDC client
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            OidcClientId::new(config.client_id.clone()),
            Some(OidcClientSecret::new(config.client_secret.clone())),
        )
        .set_redirect_uri(
            OidcRedirectUrl::new(config.redirect_uri.clone())
                .map_err(|e| OAuth2Error::Configuration(e.to_string()))?,
        );

        Ok(client)
    }

    /// Generate an authorization URL for the OAuth2 flow
    ///
    /// Returns (authorization_url, state, pkce_verifier, nonce)
    pub fn authorization_url(&self) -> (Url, CsrfToken, Option<PkceCodeVerifier>, Option<Nonce>) {
        if let Some(oidc_client) = &self.oidc_client {
            // OIDC flow with nonce
            let mut auth_request = oidc_client.authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            );

            // Add scopes
            for scope in &self.config.scopes {
                auth_request = auth_request.add_scope(openidconnect::Scope::new(scope.clone()));
            }

            // Add PKCE if enabled
            let pkce_verifier = if self.config.use_pkce {
                let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
                auth_request = auth_request.set_pkce_challenge(pkce_challenge);
                Some(pkce_verifier)
            } else {
                None
            };

            let (url, state, nonce) = auth_request.url();
            (url, state, pkce_verifier, Some(nonce))
        } else {
            // Standard OAuth2 flow
            let mut auth_request = self.oauth2_client.authorize_url(CsrfToken::new_random);

            // Add scopes
            for scope in &self.config.scopes {
                auth_request = auth_request.add_scope(Scope::new(scope.clone()));
            }

            // Add PKCE if enabled
            let pkce_verifier = if self.config.use_pkce {
                let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
                auth_request = auth_request.set_pkce_challenge(pkce_challenge);
                Some(pkce_verifier)
            } else {
                None
            };

            let (url, state) = auth_request.url();
            (url, state, pkce_verifier, None)
        }
    }

    /// Exchange authorization code for tokens
    pub async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: Option<PkceCodeVerifier>,
        nonce: Option<&Nonce>,
    ) -> Result<(OAuth2User, Option<OidcUser>), OAuth2Error> {
        if let Some(oidc_client) = &self.oidc_client {
            // OIDC token exchange using openidconnect's async client
            let mut token_request =
                oidc_client.exchange_code(AuthorizationCode::new(code.to_string()));

            if let Some(verifier) = pkce_verifier {
                token_request = token_request.set_pkce_verifier(verifier);
            }

            let token_response = token_request
                .request_async(openidconnect::reqwest::async_http_client)
                .await
                .map_err(|e| OAuth2Error::TokenExchange(format!("{:?}", e)))?;

            // Verify and extract ID token claims
            let id_token = token_response
                .id_token()
                .ok_or_else(|| OAuth2Error::TokenValidation("Missing ID token".to_string()))?;

            let id_token_verifier = oidc_client.id_token_verifier();
            let nonce_ref = nonce.cloned().unwrap_or_else(|| Nonce::new(String::new()));
            let claims = id_token.claims(&id_token_verifier, &nonce_ref).map_err(
                |e: openidconnect::ClaimsVerificationError| {
                    OAuth2Error::TokenValidation(e.to_string())
                },
            )?;

            // Extract basic info from claims
            let subject = claims.subject().as_str().to_string();
            let issuer = claims.issuer().as_str().to_string();
            let exp = claims.expiration().timestamp();
            let iat = claims.issue_time().timestamp();

            // Build OAuth2User
            let mut oauth2_user = OAuth2User::new(&subject, &self.config.registration_id);
            oauth2_user.access_token = Some(token_response.access_token().secret().clone());
            oauth2_user.refresh_token = token_response.refresh_token().map(|t| t.secret().clone());
            oauth2_user.email_verified = claims.email_verified();

            // Build OidcUser with basic claims
            let oidc_user = OidcUser {
                oauth2_user: oauth2_user.clone(),
                id_token_claims: Some(IdTokenClaims {
                    iss: issuer,
                    sub: subject,
                    aud: vec![self.config.client_id.clone()],
                    exp,
                    iat,
                    auth_time: None,
                    nonce: None,
                    at_hash: None,
                }),
                id_token: Some(id_token.to_string()),
            };

            Ok((oauth2_user, Some(oidc_user)))
        } else {
            // Standard OAuth2 token exchange
            let mut token_request = self
                .oauth2_client
                .exchange_code(AuthorizationCode::new(code.to_string()));

            if let Some(verifier) = pkce_verifier {
                token_request = token_request.set_pkce_verifier(verifier);
            }

            let token_response = token_request
                .request_async(async_http_client)
                .await
                .map_err(|e| OAuth2Error::TokenExchange(e.to_string()))?;

            // Fetch user info
            let mut oauth2_user = self
                .fetch_user_info(token_response.access_token().secret())
                .await?;

            oauth2_user.access_token = Some(token_response.access_token().secret().clone());
            oauth2_user.refresh_token = token_response.refresh_token().map(|t| t.secret().clone());

            Ok((oauth2_user, None))
        }
    }

    /// Fetch user info from the provider's userinfo endpoint
    async fn fetch_user_info(&self, access_token: &str) -> Result<OAuth2User, OAuth2Error> {
        let userinfo_url = self
            .config
            .userinfo_uri
            .as_ref()
            .ok_or_else(|| OAuth2Error::UserInfo("Missing userinfo URI".to_string()))?;

        let http_client = reqwest::Client::new();
        let response = http_client
            .get(userinfo_url)
            .bearer_auth(access_token)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| OAuth2Error::UserInfo(e.to_string()))?;

        if !response.status().is_success() {
            return Err(OAuth2Error::UserInfo(format!(
                "HTTP {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            )));
        }

        let attributes: HashMap<String, serde_json::Value> = response
            .json()
            .await
            .map_err(|e| OAuth2Error::UserInfo(e.to_string()))?;

        // Extract user ID based on provider
        let sub = self.extract_user_id(&attributes)?;
        let mut user = OAuth2User::new(sub, &self.config.registration_id);
        user.access_token = Some(access_token.to_string());
        user.attributes = attributes.clone();

        // Extract common fields
        user.name = attributes
            .get("name")
            .and_then(|v| v.as_str())
            .map(String::from);
        user.email = attributes
            .get("email")
            .and_then(|v| v.as_str())
            .map(String::from);
        user.picture = attributes
            .get("picture")
            .or_else(|| attributes.get("avatar_url"))
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(user)
    }

    /// Extract user ID from attributes based on provider
    fn extract_user_id(
        &self,
        attributes: &HashMap<String, serde_json::Value>,
    ) -> Result<String, OAuth2Error> {
        // Try common ID fields
        let id_fields = ["sub", "id", "user_id", "login"];

        for field in &id_fields {
            if let Some(value) = attributes.get(*field) {
                if let Some(s) = value.as_str() {
                    return Ok(s.to_string());
                }
                if let Some(n) = value.as_i64() {
                    return Ok(n.to_string());
                }
            }
        }

        Err(OAuth2Error::UserInfo(
            "Could not extract user ID".to_string(),
        ))
    }

    /// Get the configuration
    pub fn config(&self) -> &OAuth2Config {
        &self.config
    }

    /// Check if OIDC is available
    pub fn has_oidc(&self) -> bool {
        self.oidc_client.is_some()
    }
}

/// Repository for multiple OAuth2 client registrations
///
/// Similar to Spring Security's `ClientRegistrationRepository`.
#[derive(Clone, Default)]
pub struct OAuth2ClientRepository {
    clients: HashMap<String, OAuth2Client>,
}

impl OAuth2ClientRepository {
    /// Create a new empty repository
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
        }
    }

    /// Add a client registration
    pub fn add_client(&mut self, client: OAuth2Client) {
        self.clients
            .insert(client.config.registration_id.clone(), client);
    }

    /// Get a client by registration ID
    pub fn get_client(&self, registration_id: &str) -> Option<&OAuth2Client> {
        self.clients.get(registration_id)
    }

    /// Get all registration IDs
    pub fn registration_ids(&self) -> Vec<&String> {
        self.clients.keys().collect()
    }

    /// Build a repository from multiple configurations
    pub async fn from_configs(configs: Vec<OAuth2Config>) -> Result<Self, OAuth2Error> {
        let mut repo = Self::new();
        for config in configs {
            let client = OAuth2Client::new(config).await?;
            repo.add_client(client);
        }
        Ok(repo)
    }
}

/// OAuth2 authenticator that validates OAuth2 access tokens
///
/// This authenticator checks for Bearer tokens in the Authorization header
/// and validates them against the OAuth2 provider.
#[derive(Clone)]
pub struct OAuth2Authenticator {
    /// Expected issuer for token validation
    issuer: Option<String>,
    /// JWKS for token validation
    jwks_uri: Option<String>,
    /// Attribute to use as username
    username_attribute: String,
}

impl OAuth2Authenticator {
    /// Create a new OAuth2 authenticator
    pub fn new() -> Self {
        Self {
            issuer: None,
            jwks_uri: None,
            username_attribute: "sub".to_string(),
        }
    }

    /// Set the expected issuer
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Set the JWKS URI for token validation
    pub fn jwks_uri(mut self, uri: impl Into<String>) -> Self {
        self.jwks_uri = Some(uri.into());
        self
    }

    /// Set the attribute to use as username
    pub fn username_attribute(mut self, attr: impl Into<String>) -> Self {
        self.username_attribute = attr.into();
        self
    }

    /// Extract Bearer token from request
    fn extract_token(&self, req: &ServiceRequest) -> Option<String> {
        let auth_header = req.headers().get(AUTHORIZATION)?;
        let auth_str = auth_header.to_str().ok()?;

        auth_str
            .strip_prefix("Bearer ")
            .map(|token| token.to_string())
    }
}

impl Default for OAuth2Authenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl Authenticator for OAuth2Authenticator {
    fn get_user(&self, req: &ServiceRequest) -> Option<User> {
        // This is a simplified implementation
        // In production, you would validate the token against JWKS
        let _token = self.extract_token(req)?;

        // For now, we return None as token validation requires async
        // The actual validation should be done via OAuth2CallbackHandler
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth2_config_builder() {
        let config = OAuth2Config::new("client-id", "secret", "http://localhost/callback")
            .provider(OAuth2Provider::Google)
            .add_scope("custom_scope");

        assert_eq!(config.client_id, "client-id");
        assert_eq!(config.provider, OAuth2Provider::Google);
        assert!(config.scopes.contains(&"openid".to_string()));
        assert!(config.scopes.contains(&"email".to_string()));
        assert!(config.scopes.contains(&"custom_scope".to_string()));
        assert!(config.use_pkce);
    }

    #[test]
    fn test_oauth2_provider_endpoints() {
        assert!(OAuth2Provider::Google.auth_url().is_some());
        assert!(OAuth2Provider::Google.token_url().is_some());
        assert!(OAuth2Provider::Google.userinfo_url().is_some());
        assert!(OAuth2Provider::Google.supports_oidc());

        assert!(OAuth2Provider::GitHub.auth_url().is_some());
        assert!(!OAuth2Provider::GitHub.supports_oidc());
    }

    #[test]
    fn test_oauth2_user() {
        let mut user = OAuth2User::new("user123", "google");
        user.email = Some("user@example.com".to_string());
        user.name = Some("Test User".to_string());

        assert_eq!(user.username(), "user@example.com");

        let auth_user = user.to_user();
        assert_eq!(auth_user.get_username(), "user@example.com");
        assert!(auth_user.get_roles().contains(&"USER".to_string()));
    }

    #[test]
    fn test_provider_default_scopes() {
        let google_scopes = OAuth2Provider::Google.default_scopes();
        assert!(google_scopes.contains(&"openid"));
        assert!(google_scopes.contains(&"email"));

        let github_scopes = OAuth2Provider::GitHub.default_scopes();
        assert!(github_scopes.contains(&"read:user"));
    }

    #[test]
    fn test_oauth2_client_basic() {
        let config = OAuth2Config::new("client-id", "secret", "http://localhost/callback")
            .provider(OAuth2Provider::GitHub);

        let client = OAuth2Client::new_basic(config).unwrap();
        assert!(!client.has_oidc());
    }
}
