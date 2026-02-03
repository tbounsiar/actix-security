//! WebSocket Security module for Actix Web.
//!
//! # Overview
//!
//! This module provides security features for WebSocket connections:
//! - Authentication during the WebSocket handshake
//! - Origin validation (CSWSH prevention)
//! - Security context propagation to WebSocket actors
//!
//! # How It Works
//!
//! WebSocket security works by securing the HTTP upgrade request:
//!
//! ```text
//! Client                    Server
//!   |                          |
//!   |--HTTP Upgrade Request--->|
//!   |  (with auth token)       | 1. SecurityTransform validates auth
//!   |                          | 2. Origin validation (CSWSH check)
//!   |                          | 3. Store user in extensions
//!   |<--101 Switching----------|
//!   |                          |
//!   |==WebSocket Connection====| User available via SecurityContext
//!   |                          |
//! ```
//!
//! # Usage
//!
//! ## Basic WebSocket Authentication
//!
//! ```ignore
//! use actix_web::{get, web, HttpRequest, HttpResponse};
//! use actix_security::http::security::{SecurityExt, websocket::OriginValidator};
//!
//! #[get("/ws")]
//! async fn ws_handler(
//!     req: HttpRequest,
//!     stream: web::Payload,
//! ) -> Result<HttpResponse, actix_web::Error> {
//!     // 1. Check authentication (user already set by SecurityTransform)
//!     let user = req.get_user().ok_or(AuthError::Unauthorized)?;
//!
//!     // 2. Validate origin (CSWSH prevention)
//!     OriginValidator::new(&["https://myapp.com"])
//!         .validate(&req)?;
//!
//!     // 3. Upgrade to WebSocket
//!     let resp = actix_ws::start(MyWebSocketActor::new(user), &req, stream)?;
//!     Ok(resp)
//! }
//! ```
//!
//! ## Using WebSocket Security Config
//!
//! ```ignore
//! use actix_security::http::security::websocket::WebSocketSecurityConfig;
//!
//! let ws_config = WebSocketSecurityConfig::new()
//!     .allowed_origins(vec!["https://myapp.com".into()])
//!     .require_authentication(true);
//!
//! #[get("/ws")]
//! async fn ws_handler(
//!     req: HttpRequest,
//!     stream: web::Payload,
//!     config: web::Data<WebSocketSecurityConfig>,
//! ) -> Result<HttpResponse, actix_web::Error> {
//!     // Validate the upgrade request
//!     let user = config.validate_upgrade(&req)?;
//!
//!     // Upgrade to WebSocket
//!     let resp = actix_ws::start(MyWebSocketActor::new(user), &req, stream)?;
//!     Ok(resp)
//! }
//! ```
//!
//! ## Security Context in WebSocket Actor
//!
//! ```ignore
//! use actix_security::http::security::{User, SecurityContext};
//!
//! struct MyWebSocketActor {
//!     user: User,
//! }
//!
//! impl MyWebSocketActor {
//!     pub fn new(user: User) -> Self {
//!         Self { user }
//!     }
//!
//!     fn handle_message(&self, msg: &str) {
//!         // Access user directly
//!         if self.user.has_role("ADMIN") {
//!             // Admin-only logic
//!         }
//!     }
//! }
//! ```
//!
//! # Spring Security Comparison
//!
//! | Spring Security | Actix Security |
//! |-----------------|----------------|
//! | `WebSocketSecurityConfigurer` | `WebSocketSecurityConfig` |
//! | `AbstractSecurityWebSocketMessageBrokerConfigurer` | Security middleware + OriginValidator |
//! | `@PreAuthorize` on message handlers | Manual checks in actor |
//! | CORS/Origin checking | `OriginValidator` |
//!
//! # Security Best Practices
//!
//! 1. **Always use TLS** - Use `wss://` in production
//! 2. **Validate Origin** - Prevent Cross-Site WebSocket Hijacking (CSWSH)
//! 3. **Authenticate during handshake** - Before WebSocket upgrade
//! 4. **Set message size limits** - Prevent DoS attacks
//! 5. **Implement timeouts** - Close idle connections

mod config;
mod error;
mod extractor;
mod origin;

pub use config::{WebSocketSecurityConfig, WebSocketSecurityConfigBuilder};
pub use error::WebSocketSecurityError;
pub use extractor::{WebSocketUpgrade, WebSocketUser};
pub use origin::{OriginValidator, OriginValidatorBuilder};
