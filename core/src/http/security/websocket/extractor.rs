//! WebSocket-specific extractors for security context.
//!
//! These extractors help access the authenticated user during WebSocket
//! upgrade handling, before the connection is established.

use actix_web::HttpRequest;

use crate::http::security::User;

use super::error::WebSocketSecurityError;

/// Wrapper for extracting an authenticated user during WebSocket upgrade.
///
/// This is a convenience wrapper that extracts the `User` from the `HttpRequest`
/// extensions during the WebSocket handshake phase.
///
/// # Spring Security Equivalent
/// `@AuthenticationPrincipal` in a WebSocket handler
///
/// # Example
///
/// ```ignore
/// use actix_web::{get, web, HttpRequest, HttpResponse};
/// use actix_security::http::security::websocket::WebSocketUser;
///
/// #[get("/ws")]
/// async fn ws_handler(
///     req: HttpRequest,
///     stream: web::Payload,
/// ) -> Result<HttpResponse, actix_web::Error> {
///     // Extract user - returns error if not authenticated
///     let user = WebSocketUser::extract(&req)?;
///
///     // Pass user to WebSocket actor
///     let resp = actix_ws::start(MyActor::new(user.into_inner()), &req, stream)?;
///     Ok(resp)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct WebSocketUser(User);

impl WebSocketUser {
    /// Extracts the authenticated user from the request.
    ///
    /// # Errors
    /// Returns `WebSocketSecurityError::Unauthorized` if no user is present.
    pub fn extract(req: &HttpRequest) -> Result<Self, WebSocketSecurityError> {
        use actix_web::HttpMessage;

        req.extensions()
            .get::<User>()
            .cloned()
            .map(WebSocketUser)
            .ok_or(WebSocketSecurityError::Unauthorized)
    }

    /// Extracts the user if present, otherwise returns None.
    pub fn try_extract(req: &HttpRequest) -> Option<Self> {
        use actix_web::HttpMessage;

        req.extensions().get::<User>().cloned().map(WebSocketUser)
    }

    /// Returns the inner User.
    pub fn into_inner(self) -> User {
        self.0
    }

    /// Returns a reference to the inner User.
    pub fn as_user(&self) -> &User {
        &self.0
    }

    /// Checks if the user has the specified role.
    pub fn has_role(&self, role: &str) -> bool {
        self.0.has_role(role)
    }

    /// Checks if the user has any of the specified roles.
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        self.0.has_any_role(roles)
    }

    /// Checks if the user has the specified authority.
    pub fn has_authority(&self, authority: &str) -> bool {
        self.0.has_authority(authority)
    }

    /// Checks if the user has any of the specified authorities.
    pub fn has_any_authority(&self, authorities: &[&str]) -> bool {
        self.0.has_any_authority(authorities)
    }

    /// Returns the username.
    pub fn get_username(&self) -> &str {
        self.0.get_username()
    }

    /// Requires the user to have the specified role.
    ///
    /// # Errors
    /// Returns `WebSocketSecurityError::MissingRole` if the user doesn't have the role.
    pub fn require_role(self, role: &str) -> Result<Self, WebSocketSecurityError> {
        if self.has_role(role) {
            Ok(self)
        } else {
            Err(WebSocketSecurityError::MissingRole {
                role: role.to_string(),
            })
        }
    }

    /// Requires the user to have any of the specified roles.
    ///
    /// # Errors
    /// Returns `WebSocketSecurityError::MissingRole` if the user doesn't have any of the roles.
    pub fn require_any_role(self, roles: &[&str]) -> Result<Self, WebSocketSecurityError> {
        if self.has_any_role(roles) {
            Ok(self)
        } else {
            Err(WebSocketSecurityError::MissingRole {
                role: roles.join(", "),
            })
        }
    }

    /// Requires the user to have the specified authority.
    ///
    /// # Errors
    /// Returns `WebSocketSecurityError::MissingAuthority` if the user doesn't have the authority.
    pub fn require_authority(self, authority: &str) -> Result<Self, WebSocketSecurityError> {
        if self.has_authority(authority) {
            Ok(self)
        } else {
            Err(WebSocketSecurityError::MissingAuthority {
                authority: authority.to_string(),
            })
        }
    }

    /// Requires the user to have any of the specified authorities.
    ///
    /// # Errors
    /// Returns `WebSocketSecurityError::MissingAuthority` if the user doesn't have any of the authorities.
    pub fn require_any_authority(
        self,
        authorities: &[&str],
    ) -> Result<Self, WebSocketSecurityError> {
        if self.has_any_authority(authorities) {
            Ok(self)
        } else {
            Err(WebSocketSecurityError::MissingAuthority {
                authority: authorities.join(", "),
            })
        }
    }
}

impl std::ops::Deref for WebSocketUser {
    type Target = User;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<WebSocketUser> for User {
    fn from(ws_user: WebSocketUser) -> Self {
        ws_user.0
    }
}

/// Represents a validated WebSocket upgrade request.
///
/// This struct is returned after validating both authentication and origin,
/// indicating that the WebSocket upgrade can proceed safely.
///
/// # Example
///
/// ```ignore
/// use actix_security::http::security::websocket::{WebSocketSecurityConfig, WebSocketUpgrade};
///
/// let config = WebSocketSecurityConfig::new()
///     .allowed_origins(vec!["https://myapp.com".into()])
///     .require_authentication(true);
///
/// #[get("/ws")]
/// async fn ws_handler(
///     req: HttpRequest,
///     stream: web::Payload,
///     config: web::Data<WebSocketSecurityConfig>,
/// ) -> Result<HttpResponse, actix_web::Error> {
///     // Validates auth and origin in one step
///     let upgrade = config.validate_upgrade(&req)?;
///
///     // Access the user
///     let user = upgrade.user();
///
///     // Proceed with upgrade
///     let resp = actix_ws::start(MyActor::new(user.clone()), &req, stream)?;
///     Ok(resp)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct WebSocketUpgrade {
    user: Option<User>,
    origin: Option<String>,
}

impl WebSocketUpgrade {
    /// Creates a new WebSocketUpgrade.
    pub fn new(user: Option<User>, origin: Option<String>) -> Self {
        Self { user, origin }
    }

    /// Returns the authenticated user, if any.
    pub fn user(&self) -> Option<&User> {
        self.user.as_ref()
    }

    /// Consumes self and returns the user.
    pub fn into_user(self) -> Option<User> {
        self.user
    }

    /// Returns the origin header value, if present.
    pub fn origin(&self) -> Option<&str> {
        self.origin.as_deref()
    }

    /// Returns true if the request came from an authenticated user.
    pub fn is_authenticated(&self) -> bool {
        self.user.is_some()
    }

    /// Returns the username if authenticated.
    pub fn username(&self) -> Option<&str> {
        self.user.as_ref().map(|u| u.get_username())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test::TestRequest, HttpMessage};

    #[test]
    fn test_websocket_user_extract_success() {
        let user = User::new("testuser".into(), "password".into());
        let req = TestRequest::default().to_http_request();
        req.extensions_mut().insert(user.clone());

        let ws_user = WebSocketUser::extract(&req).unwrap();
        assert_eq!(ws_user.get_username(), "testuser");
    }

    #[test]
    fn test_websocket_user_extract_unauthorized() {
        let req = TestRequest::default().to_http_request();

        let result = WebSocketUser::extract(&req);
        assert!(matches!(result, Err(WebSocketSecurityError::Unauthorized)));
    }

    #[test]
    fn test_websocket_user_try_extract() {
        let req = TestRequest::default().to_http_request();
        assert!(WebSocketUser::try_extract(&req).is_none());

        let user = User::new("testuser".into(), "password".into());
        req.extensions_mut().insert(user);
        assert!(WebSocketUser::try_extract(&req).is_some());
    }

    #[test]
    fn test_websocket_user_require_role() {
        let user = User::new("admin".into(), "password".into()).roles(&["ADMIN".into()]);
        let req = TestRequest::default().to_http_request();
        req.extensions_mut().insert(user);

        let ws_user = WebSocketUser::extract(&req).unwrap();

        // Should succeed
        assert!(ws_user.clone().require_role("ADMIN").is_ok());

        // Should fail
        assert!(matches!(
            ws_user.require_role("SUPERADMIN"),
            Err(WebSocketSecurityError::MissingRole { role }) if role == "SUPERADMIN"
        ));
    }

    #[test]
    fn test_websocket_user_require_authority() {
        let user = User::new("user".into(), "password".into()).authorities(&["ws:connect".into()]);
        let req = TestRequest::default().to_http_request();
        req.extensions_mut().insert(user);

        let ws_user = WebSocketUser::extract(&req).unwrap();

        // Should succeed
        assert!(ws_user.clone().require_authority("ws:connect").is_ok());

        // Should fail
        assert!(matches!(
            ws_user.require_authority("ws:admin"),
            Err(WebSocketSecurityError::MissingAuthority { authority }) if authority == "ws:admin"
        ));
    }

    #[test]
    fn test_websocket_upgrade() {
        let user = User::new("testuser".into(), "password".into());
        let upgrade = WebSocketUpgrade::new(Some(user), Some("https://myapp.com".into()));

        assert!(upgrade.is_authenticated());
        assert_eq!(upgrade.username(), Some("testuser"));
        assert_eq!(upgrade.origin(), Some("https://myapp.com"));
    }

    #[test]
    fn test_websocket_upgrade_anonymous() {
        let upgrade = WebSocketUpgrade::new(None, Some("https://myapp.com".into()));

        assert!(!upgrade.is_authenticated());
        assert_eq!(upgrade.username(), None);
        assert_eq!(upgrade.origin(), Some("https://myapp.com"));
    }
}
