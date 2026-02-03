//! API Key authentication error types.

use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use derive_more::{Display, Error};

/// Errors that can occur during API key authentication.
#[derive(Debug, Display, Error)]
pub enum ApiKeyError {
    /// No API key was found in the request.
    #[display("Unauthorized: API key not provided")]
    Missing,

    /// The API key format is invalid.
    #[display("Unauthorized: invalid API key format")]
    InvalidFormat,

    /// The API key is not recognized or has been revoked.
    #[display("Unauthorized: invalid API key")]
    Invalid,

    /// The API key has expired.
    #[display("Unauthorized: API key has expired")]
    Expired,

    /// The API key is disabled.
    #[display("Unauthorized: API key is disabled")]
    Disabled,

    /// The API key doesn't have the required permissions.
    #[display("Forbidden: insufficient API key permissions")]
    InsufficientPermissions,

    /// Rate limit exceeded for this API key.
    #[display("Too Many Requests: rate limit exceeded for this API key")]
    RateLimitExceeded,
}

impl ResponseError for ApiKeyError {
    fn status_code(&self) -> StatusCode {
        match self {
            ApiKeyError::Missing
            | ApiKeyError::InvalidFormat
            | ApiKeyError::Invalid
            | ApiKeyError::Expired
            | ApiKeyError::Disabled => StatusCode::UNAUTHORIZED,
            ApiKeyError::InsufficientPermissions => StatusCode::FORBIDDEN,
            ApiKeyError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        let error = status.canonical_reason().unwrap_or("Error");
        let message = self.to_string();
        let body = format!(r#"{{"error":"{}","message":"{}"}}"#, error, message);

        HttpResponse::build(status)
            .content_type("application/json")
            .body(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_status() {
        let err = ApiKeyError::Missing;
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_invalid_status() {
        let err = ApiKeyError::Invalid;
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_insufficient_permissions_status() {
        let err = ApiKeyError::InsufficientPermissions;
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_rate_limit_status() {
        let err = ApiKeyError::RateLimitExceeded;
        assert_eq!(err.status_code(), StatusCode::TOO_MANY_REQUESTS);
    }
}
