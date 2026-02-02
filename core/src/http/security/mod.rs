//! Security module providing authentication and authorization.
//!
//! # Spring Equivalent
//! `org.springframework.security` package
//!
//! # Module Structure
//!
//! - `authenticator` - User authentication implementations (MemoryAuthenticator)
//! - `authorizer` - Request authorization implementations (RequestMatcherAuthorizer)
//! - `config` - Core traits (Authenticator, Authorizer)
//! - `crypto` - Password encoding (Argon2, BCrypt, NoOp, Delegating)
//! - `extractor` - Actix Web extractors (AuthenticatedUser, OptionalUser)
//! - `http_basic` - HTTP Basic Authentication support
//! - `jwt` - JWT (JSON Web Token) Authentication
//! - `session` - Session-based Authentication
//! - `manager` - Factory methods (AuthenticationManager, AuthorizationManager)
//! - `middleware` - Security middleware (SecurityTransform)
//! - `user` - User model
//! - `web` - Re-exports for backward compatibility
//! - `expression` - Security Expression Language (SpEL-like)
//! - `context` - Security context for accessing current user
//! - `headers` - Security headers middleware (X-Frame-Options, CSP, HSTS, etc.)
//! - `rate_limit` - Rate limiting middleware (brute-force protection)
//! - `audit` - Security audit logging
//! - `account` - Account locking on failed attempts
//! - `ldap` - LDAP/Active Directory Authentication
//! - `saml` - SAML 2.0 Single Sign-On
//! - `ant_matcher` - Ant-style URL pattern matching
//! - `channel` - Channel security (HTTPS enforcement)
//!
//! # Feature Flags
//! - `argon2`: Enables `Argon2PasswordEncoder` and `DelegatingPasswordEncoder`
//! - `bcrypt`: Enables `BCryptPasswordEncoder`
//! - `http-basic`: Enables HTTP Basic Authentication
//! - `jwt`: Enables JWT Authentication
//! - `session`: Enables Session-based Authentication
//! - `oauth2`: Enables OAuth2/OIDC Authentication
//! - `rate-limit`: Enables Rate Limiting middleware
//! - `audit`: Enables Security Audit Logging
//! - `account-lock`: Enables Account Locking
//! - `ldap`: Enables LDAP/Active Directory Authentication
//! - `saml`: Enables SAML 2.0 Single Sign-On

// Re-exports for convenience
pub use authenticator::MemoryAuthenticator;
pub use authorizer::{Access, RequestMatcherAuthorizer};
pub use config::{Authenticator, Authorizer};
pub use crypto::{NoOpPasswordEncoder, PasswordEncoder};
#[cfg(feature = "argon2")]
pub use crypto::{Argon2PasswordEncoder, DelegatingPasswordEncoder, DefaultEncoder};
#[cfg(feature = "bcrypt")]
pub use crypto::BCryptPasswordEncoder;
pub use extractor::{AuthenticatedUser, OptionalUser, SecurityExt};
#[cfg(feature = "http-basic")]
pub use http_basic::HttpBasicConfig;
#[cfg(feature = "jwt")]
pub use jwt::{JwtAuthenticator, JwtConfig, JwtTokenService, Claims as JwtClaims};
#[cfg(feature = "session")]
pub use session::{
    CredentialAuthenticator, SessionAuthenticator, SessionConfig, SessionError,
    SessionFixationStrategy, SessionLoginService, SessionUser,
};
#[cfg(feature = "remember-me")]
pub use remember_me::{RememberMeConfig, RememberMeError, RememberMeServices, RememberMeToken};
#[cfg(feature = "csrf")]
pub use csrf::{CsrfConfig, CsrfError, CsrfProtection, CsrfToken, CsrfTokenRepository, SessionCsrfTokenRepository};
#[cfg(feature = "form-login")]
pub use form_login::{FormLoginConfig, FormLoginError, FormLoginHandler, FormLoginService, LoginForm};
#[cfg(feature = "user-details")]
pub use user_details::{
    CachingUserDetailsService, InMemoryUserDetailsService, UserDetailsAuthenticator,
    UserDetailsError, UserDetailsManager, UserDetailsService,
};
#[cfg(feature = "oauth2")]
pub use oauth2::{OAuth2Authenticator, OAuth2Client, OAuth2Config, OAuth2Provider, OAuth2User, OidcUser};
pub use context::SecurityContext;
pub use headers::SecurityHeaders;
pub use manager::{AuthenticationManager, AuthorizationManager};
pub use user::User;
#[cfg(feature = "rate-limit")]
pub use rate_limit::{
    KeyExtractor, RateLimitAlgorithm, RateLimitConfig, RateLimitInfo, RateLimiter,
    RateLimiterState,
};
#[cfg(feature = "audit")]
pub use audit::{
    audit_log, global_logger, init_global_logger, AuditLogger, InMemoryEventStore,
    SecurityEvent, SecurityEventHandler, SecurityEventSeverity, SecurityEventType, StdoutHandler,
};
#[cfg(feature = "account-lock")]
pub use account::{
    check_login, AccountLockManager, AccountStats, LockConfig, LockStatus, LoginCheckResult,
};
#[cfg(feature = "ldap")]
pub use ldap::{
    LdapAuthResult, LdapAuthenticator, LdapConfig, LdapContextMapper, LdapError, MockLdapClient,
};
#[cfg(feature = "saml")]
pub use saml::{
    AuthnContextClass, AuthnRequest, NameIdFormat, SamlAssertion, SamlAuthResult,
    SamlAuthenticator, SamlBinding, SamlConfig, SamlError, SamlResponse, SamlStatusCode,
};
pub use ant_matcher::{AntMatcher, AntMatcherBuilder, AntMatchers, IntoAntMatcher};
pub use channel::{ChannelRequirement, ChannelSecurity, ChannelSecurityConfig, PortMapper};

// Internal modules (private implementation details)
mod config;
mod extractor;
mod user;

// Public modules
pub mod authenticator;
pub mod authorizer;
pub mod context;
pub mod crypto;
pub mod expression;
pub mod headers;
pub mod http_basic;
#[cfg(feature = "jwt")]
pub mod jwt;
#[cfg(feature = "session")]
pub mod session;
#[cfg(feature = "remember-me")]
pub mod remember_me;
#[cfg(feature = "csrf")]
pub mod csrf;
#[cfg(feature = "form-login")]
pub mod form_login;
#[cfg(feature = "user-details")]
pub mod user_details;
#[cfg(feature = "oauth2")]
pub mod oauth2;
#[cfg(feature = "rate-limit")]
pub mod rate_limit;
#[cfg(feature = "audit")]
pub mod audit;
#[cfg(feature = "account-lock")]
pub mod account;
#[cfg(feature = "ldap")]
pub mod ldap;
#[cfg(feature = "saml")]
pub mod saml;
pub mod ant_matcher;
pub mod channel;
pub mod manager;
pub mod middleware;

// Backward compatibility module
pub mod web;
