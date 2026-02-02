//! # Actix Security
//!
//! Spring Security-inspired authentication and authorization for Actix Web.
//!
//! This crate provides a unified API combining:
//! - `actix-security-core`: Security middleware, authentication, and authorization
//! - `actix-security-codegen`: Procedural macros (`#[secured]`, `#[pre_authorize]`, etc.)
//!
//! ## Quick Start
//!
//! Add to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! actix-web = "4"
//! actix-security = { version = "0.2", features = ["argon2", "http-basic"] }
//! ```
//!
//! ## Example
//!
//! ```rust,ignore
//! use actix_web::{get, App, HttpServer, HttpResponse, Responder};
//! use actix_security::{secured, pre_authorize};
//! use actix_security::http::security::{
//!     AuthenticatedUser, AuthenticationManager, AuthorizationManager,
//!     Argon2PasswordEncoder, PasswordEncoder, User,
//! };
//! use actix_security::http::security::middleware::SecurityTransform;
//!
//! #[secured("ADMIN")]
//! #[get("/admin")]
//! async fn admin(user: AuthenticatedUser) -> impl Responder {
//!     HttpResponse::Ok().body(format!("Welcome, Admin {}!", user.get_username()))
//! }
//!
//! #[pre_authorize("hasRole('USER') AND hasAuthority('posts:write')")]
//! #[post("/posts")]
//! async fn create_post(user: AuthenticatedUser) -> impl Responder {
//!     HttpResponse::Created().body("Post created")
//! }
//! ```
//!
//! ## Features
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `macros` | Yes | Procedural macros (`#[secured]`, `#[pre_authorize]`, etc.) |
//! | `argon2` | Yes | Argon2 password encoder |
//! | `http-basic` | Yes | HTTP Basic authentication |
//! | `jwt` | No | JWT authentication (with RSA support) |
//! | `session` | No | Session-based authentication with fixation protection |
//! | `form-login` | No | Form-based login with redirect support |
//! | `remember-me` | No | Remember-me persistent authentication |
//! | `csrf` | No | CSRF protection middleware |
//! | `oauth2` | No | OAuth2/OIDC authentication |
//! | `user-details` | No | Async UserDetailsService trait |
//! | `full` | No | All features enabled |
//!
//! ## Modules
//!
//! The main functionality is available through the `http` module:
//!
//! - [`http::security`] - Authentication, authorization, and middleware
//! - [`http::error`] - Error types

// Re-export everything from actix-security-core
pub use actix_security_core::*;

// Re-export procedural macros when the "macros" feature is enabled
#[cfg(feature = "macros")]
pub use actix_security_codegen::*;

/// Prelude module for convenient imports
pub mod prelude {
    pub use actix_security_core::http::security::{
        AuthenticatedUser, Authenticator, Authorizer, PasswordEncoder, SecurityContext,
        SecurityHeaders, User,
    };

    #[cfg(feature = "argon2")]
    pub use actix_security_core::http::security::Argon2PasswordEncoder;

    #[cfg(feature = "jwt")]
    pub use actix_security_core::http::security::{JwtAuthenticator, JwtConfig, JwtTokenService};

    #[cfg(feature = "session")]
    pub use actix_security_core::http::security::{
        SessionAuthenticator, SessionConfig, SessionLoginService,
    };

    #[cfg(feature = "form-login")]
    pub use actix_security_core::http::security::{
        FormLoginConfig, FormLoginHandler, FormLoginService,
    };

    #[cfg(feature = "csrf")]
    pub use actix_security_core::http::security::{CsrfConfig, CsrfProtection, CsrfToken};

    #[cfg(feature = "remember-me")]
    pub use actix_security_core::http::security::{RememberMeConfig, RememberMeServices};

    #[cfg(feature = "user-details")]
    pub use actix_security_core::http::security::{UserDetailsAuthenticator, UserDetailsService};

    #[cfg(feature = "macros")]
    pub use actix_security_codegen::{
        deny_all, has_access, permit_all, pre_authorize, roles_allowed, secured,
    };
}
