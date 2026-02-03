//! WebSocket security error types.

use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use derive_more::{Display, Error};

/// Errors that can occur during WebSocket security validation.
#[derive(Debug, Display, Error)]
pub enum WebSocketSecurityError {
    /// The user is not authenticated.
    ///
    /// Returned when a WebSocket upgrade request is made without valid authentication
    /// and `require_authentication` is enabled.
    #[display("Unauthorized: authentication required for WebSocket connection")]
    Unauthorized,

    /// The Origin header is missing.
    ///
    /// For security, browsers always send an Origin header with WebSocket requests.
    /// A missing Origin header suggests a non-browser client or a security issue.
    #[display("Forbidden: missing Origin header")]
    MissingOrigin,

    /// The Origin header value is not in the allowed origins list.
    ///
    /// This prevents Cross-Site WebSocket Hijacking (CSWSH) attacks where
    /// a malicious website tries to establish a WebSocket connection to your server
    /// using the victim's cookies.
    #[display("Forbidden: origin '{origin}' is not allowed")]
    InvalidOrigin {
        /// The origin that was rejected
        origin: String,
    },

    /// The user does not have the required role.
    #[display("Forbidden: required role '{role}' not found")]
    MissingRole {
        /// The role that was required
        role: String,
    },

    /// The user does not have the required authority.
    #[display("Forbidden: required authority '{authority}' not found")]
    MissingAuthority {
        /// The authority that was required
        authority: String,
    },
}

impl ResponseError for WebSocketSecurityError {
    fn status_code(&self) -> StatusCode {
        match self {
            WebSocketSecurityError::Unauthorized => StatusCode::UNAUTHORIZED,
            WebSocketSecurityError::MissingOrigin
            | WebSocketSecurityError::InvalidOrigin { .. }
            | WebSocketSecurityError::MissingRole { .. }
            | WebSocketSecurityError::MissingAuthority { .. } => StatusCode::FORBIDDEN,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).body(self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unauthorized_status() {
        let err = WebSocketSecurityError::Unauthorized;
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_invalid_origin_status() {
        let err = WebSocketSecurityError::InvalidOrigin {
            origin: "https://evil.com".into(),
        };
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
        assert!(err.to_string().contains("evil.com"));
    }

    #[test]
    fn test_missing_origin_status() {
        let err = WebSocketSecurityError::MissingOrigin;
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_missing_role_status() {
        let err = WebSocketSecurityError::MissingRole {
            role: "ADMIN".into(),
        };
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
        assert!(err.to_string().contains("ADMIN"));
    }

    #[test]
    fn test_missing_authority_status() {
        let err = WebSocketSecurityError::MissingAuthority {
            authority: "ws:connect".into(),
        };
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
        assert!(err.to_string().contains("ws:connect"));
    }
}
