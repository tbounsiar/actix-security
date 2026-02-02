//! Re-exports for backward compatibility.
//!
//! # Deprecated
//! This module is kept for backward compatibility.
//! Import directly from `actix_security_core::http::security` instead.
//!
//! # Spring Security Equivalent
//! `org.springframework.security.web`

// Re-export all public types for backward compatibility
pub use crate::http::security::authenticator::MemoryAuthenticator;
pub use crate::http::security::authorizer::{Access, RequestMatcherAuthorizer};
#[cfg(feature = "http-basic")]
pub use crate::http::security::http_basic::HttpBasicConfig;
