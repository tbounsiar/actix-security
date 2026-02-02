//! Security Audit Logging system.
//!
//! Provides comprehensive logging of security-related events for compliance,
//! debugging, and threat detection.
//!
//! # Spring Security Equivalent
//! Similar to Spring Security's `AuthenticationEventPublisher` and
//! `ApplicationEventPublisher` for security events.
//!
//! # Example
//!
//! ```ignore
//! use actix_security::http::security::audit::{AuditLogger, SecurityEvent};
//!
//! // Create an audit logger
//! let audit_logger = AuditLogger::new()
//!     .with_handler(|event| {
//!         println!("[AUDIT] {:?}", event);
//!     });
//!
//! // Log events
//! audit_logger.log(SecurityEvent::login_success("admin", "192.168.1.1"));
//! ```

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

/// Security event types for audit logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityEventType {
    // Authentication events
    /// Successful login
    AuthenticationSuccess,
    /// Failed login attempt
    AuthenticationFailure,
    /// User logout
    Logout,
    /// Session created
    SessionCreated,
    /// Session destroyed
    SessionDestroyed,
    /// Session expired
    SessionExpired,

    // Authorization events
    /// Access granted to resource
    AccessGranted,
    /// Access denied to resource
    AccessDenied,
    /// Insufficient permissions
    InsufficientPermissions,

    // Account events
    /// Account locked due to failed attempts
    AccountLocked,
    /// Account unlocked
    AccountUnlocked,
    /// Password changed
    PasswordChanged,
    /// Password reset requested
    PasswordResetRequested,

    // Token events
    /// Token generated
    TokenGenerated,
    /// Token refreshed
    TokenRefreshed,
    /// Token revoked
    TokenRevoked,
    /// Token expired
    TokenExpired,
    /// Invalid token used
    InvalidToken,

    // Rate limiting events
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Rate limit warning (approaching limit)
    RateLimitWarning,

    // CSRF events
    /// CSRF validation failed
    CsrfValidationFailed,
    /// Missing CSRF token
    CsrfTokenMissing,

    // Suspicious activity
    /// Potential brute force attack detected
    BruteForceDetected,
    /// Suspicious IP address
    SuspiciousIp,
    /// Multiple failed attempts from same source
    MultipleFailures,

    // Custom events
    /// Custom security event
    Custom(String),
}

impl fmt::Display for SecurityEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityEventType::AuthenticationSuccess => write!(f, "AUTHENTICATION_SUCCESS"),
            SecurityEventType::AuthenticationFailure => write!(f, "AUTHENTICATION_FAILURE"),
            SecurityEventType::Logout => write!(f, "LOGOUT"),
            SecurityEventType::SessionCreated => write!(f, "SESSION_CREATED"),
            SecurityEventType::SessionDestroyed => write!(f, "SESSION_DESTROYED"),
            SecurityEventType::SessionExpired => write!(f, "SESSION_EXPIRED"),
            SecurityEventType::AccessGranted => write!(f, "ACCESS_GRANTED"),
            SecurityEventType::AccessDenied => write!(f, "ACCESS_DENIED"),
            SecurityEventType::InsufficientPermissions => write!(f, "INSUFFICIENT_PERMISSIONS"),
            SecurityEventType::AccountLocked => write!(f, "ACCOUNT_LOCKED"),
            SecurityEventType::AccountUnlocked => write!(f, "ACCOUNT_UNLOCKED"),
            SecurityEventType::PasswordChanged => write!(f, "PASSWORD_CHANGED"),
            SecurityEventType::PasswordResetRequested => write!(f, "PASSWORD_RESET_REQUESTED"),
            SecurityEventType::TokenGenerated => write!(f, "TOKEN_GENERATED"),
            SecurityEventType::TokenRefreshed => write!(f, "TOKEN_REFRESHED"),
            SecurityEventType::TokenRevoked => write!(f, "TOKEN_REVOKED"),
            SecurityEventType::TokenExpired => write!(f, "TOKEN_EXPIRED"),
            SecurityEventType::InvalidToken => write!(f, "INVALID_TOKEN"),
            SecurityEventType::RateLimitExceeded => write!(f, "RATE_LIMIT_EXCEEDED"),
            SecurityEventType::RateLimitWarning => write!(f, "RATE_LIMIT_WARNING"),
            SecurityEventType::CsrfValidationFailed => write!(f, "CSRF_VALIDATION_FAILED"),
            SecurityEventType::CsrfTokenMissing => write!(f, "CSRF_TOKEN_MISSING"),
            SecurityEventType::BruteForceDetected => write!(f, "BRUTE_FORCE_DETECTED"),
            SecurityEventType::SuspiciousIp => write!(f, "SUSPICIOUS_IP"),
            SecurityEventType::MultipleFailures => write!(f, "MULTIPLE_FAILURES"),
            SecurityEventType::Custom(name) => write!(f, "CUSTOM_{}", name.to_uppercase()),
        }
    }
}

/// Severity level of security events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum SecurityEventSeverity {
    /// Informational (successful operations)
    #[default]
    Info,
    /// Warning (potential issues)
    Warning,
    /// Error (failed operations)
    Error,
    /// Critical (security threats)
    Critical,
}

impl fmt::Display for SecurityEventSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityEventSeverity::Info => write!(f, "INFO"),
            SecurityEventSeverity::Warning => write!(f, "WARNING"),
            SecurityEventSeverity::Error => write!(f, "ERROR"),
            SecurityEventSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl SecurityEventType {
    /// Get the default severity for this event type.
    pub fn default_severity(&self) -> SecurityEventSeverity {
        match self {
            SecurityEventType::AuthenticationSuccess
            | SecurityEventType::Logout
            | SecurityEventType::SessionCreated
            | SecurityEventType::AccessGranted
            | SecurityEventType::TokenGenerated
            | SecurityEventType::TokenRefreshed
            | SecurityEventType::PasswordChanged => SecurityEventSeverity::Info,

            SecurityEventType::SessionExpired
            | SecurityEventType::TokenExpired
            | SecurityEventType::RateLimitWarning => SecurityEventSeverity::Warning,

            SecurityEventType::AuthenticationFailure
            | SecurityEventType::SessionDestroyed
            | SecurityEventType::AccessDenied
            | SecurityEventType::InsufficientPermissions
            | SecurityEventType::TokenRevoked
            | SecurityEventType::InvalidToken
            | SecurityEventType::RateLimitExceeded
            | SecurityEventType::CsrfValidationFailed
            | SecurityEventType::CsrfTokenMissing
            | SecurityEventType::AccountLocked
            | SecurityEventType::PasswordResetRequested => SecurityEventSeverity::Error,

            SecurityEventType::BruteForceDetected
            | SecurityEventType::SuspiciousIp
            | SecurityEventType::MultipleFailures => SecurityEventSeverity::Critical,

            SecurityEventType::AccountUnlocked | SecurityEventType::Custom(_) => {
                SecurityEventSeverity::Info
            }
        }
    }
}

/// A security audit event.
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    /// Unique event ID
    pub id: String,
    /// Event timestamp (Unix epoch milliseconds)
    pub timestamp: u64,
    /// Event type
    pub event_type: SecurityEventType,
    /// Event severity
    pub severity: SecurityEventSeverity,
    /// Username (if applicable)
    pub username: Option<String>,
    /// Source IP address
    pub ip_address: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Request path
    pub path: Option<String>,
    /// HTTP method
    pub method: Option<String>,
    /// Session ID (if applicable)
    pub session_id: Option<String>,
    /// Additional details
    pub details: HashMap<String, String>,
    /// Error message (for failure events)
    pub error: Option<String>,
}

impl SecurityEvent {
    /// Create a new security event.
    pub fn new(event_type: SecurityEventType) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            id: generate_event_id(),
            timestamp: now,
            severity: event_type.default_severity(),
            event_type,
            username: None,
            ip_address: None,
            user_agent: None,
            path: None,
            method: None,
            session_id: None,
            details: HashMap::new(),
            error: None,
        }
    }

    /// Set the username.
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Set the IP address.
    pub fn ip_address(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Set the user agent.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Set the request path.
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Set the HTTP method.
    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    /// Set the session ID.
    pub fn session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    /// Set the severity (overrides default).
    pub fn severity(mut self, severity: SecurityEventSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Add a detail.
    pub fn detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    /// Set the error message.
    pub fn error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }

    // Convenience constructors

    /// Create a login success event.
    pub fn login_success(username: &str, ip: &str) -> Self {
        Self::new(SecurityEventType::AuthenticationSuccess)
            .username(username)
            .ip_address(ip)
    }

    /// Create a login failure event.
    pub fn login_failure(username: &str, ip: &str, reason: &str) -> Self {
        Self::new(SecurityEventType::AuthenticationFailure)
            .username(username)
            .ip_address(ip)
            .error(reason)
    }

    /// Create an access denied event.
    pub fn access_denied(username: &str, path: &str, ip: &str) -> Self {
        Self::new(SecurityEventType::AccessDenied)
            .username(username)
            .path(path)
            .ip_address(ip)
    }

    /// Create a rate limit exceeded event.
    pub fn rate_limit_exceeded(ip: &str, path: &str) -> Self {
        Self::new(SecurityEventType::RateLimitExceeded)
            .ip_address(ip)
            .path(path)
    }

    /// Create an account locked event.
    pub fn account_locked(username: &str, ip: &str, reason: &str) -> Self {
        Self::new(SecurityEventType::AccountLocked)
            .username(username)
            .ip_address(ip)
            .detail("reason", reason)
    }

    /// Create a brute force detected event.
    pub fn brute_force_detected(ip: &str, attempts: u32) -> Self {
        Self::new(SecurityEventType::BruteForceDetected)
            .ip_address(ip)
            .detail("attempts", attempts.to_string())
    }

    /// Format the event as a log line.
    pub fn to_log_line(&self) -> String {
        let mut parts = vec![
            format!("[{}]", self.severity),
            format!("[{}]", self.event_type),
        ];

        if let Some(ref username) = self.username {
            parts.push(format!("user={}", username));
        }
        if let Some(ref ip) = self.ip_address {
            parts.push(format!("ip={}", ip));
        }
        if let Some(ref path) = self.path {
            parts.push(format!("path={}", path));
        }
        if let Some(ref error) = self.error {
            parts.push(format!("error=\"{}\"", error));
        }
        for (k, v) in &self.details {
            parts.push(format!("{}={}", k, v));
        }

        parts.join(" ")
    }

    /// Format the event as JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| self.to_log_line())
    }
}

impl serde::Serialize for SecurityEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SecurityEvent", 12)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("timestamp", &self.timestamp)?;
        state.serialize_field("event_type", &self.event_type.to_string())?;
        state.serialize_field("severity", &self.severity.to_string())?;
        state.serialize_field("username", &self.username)?;
        state.serialize_field("ip_address", &self.ip_address)?;
        state.serialize_field("user_agent", &self.user_agent)?;
        state.serialize_field("path", &self.path)?;
        state.serialize_field("method", &self.method)?;
        state.serialize_field("session_id", &self.session_id)?;
        state.serialize_field("details", &self.details)?;
        state.serialize_field("error", &self.error)?;
        state.end()
    }
}

/// Generate a unique event ID.
fn generate_event_id() -> String {
    use rand::Rng;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros();
    let random: u32 = rand::thread_rng().gen();
    format!("{:x}-{:08x}", timestamp, random)
}

/// Trait for handling security events.
pub trait SecurityEventHandler: Send + Sync {
    /// Handle a security event.
    fn handle(&self, event: &SecurityEvent);
}

/// Simple logging handler that prints to stdout.
#[derive(Default)]
pub struct StdoutHandler {
    min_severity: SecurityEventSeverity,
}

impl StdoutHandler {
    /// Create a new stdout handler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set minimum severity to log.
    pub fn min_severity(mut self, severity: SecurityEventSeverity) -> Self {
        self.min_severity = severity;
        self
    }
}

impl SecurityEventHandler for StdoutHandler {
    fn handle(&self, event: &SecurityEvent) {
        if event.severity >= self.min_severity {
            println!("[SECURITY] {}", event.to_log_line());
        }
    }
}

/// Handler that calls a closure.
pub struct ClosureHandler<F>
where
    F: Fn(&SecurityEvent) + Send + Sync,
{
    handler: F,
}

impl<F> ClosureHandler<F>
where
    F: Fn(&SecurityEvent) + Send + Sync,
{
    /// Create a new closure handler.
    pub fn new(handler: F) -> Self {
        Self { handler }
    }
}

impl<F> SecurityEventHandler for ClosureHandler<F>
where
    F: Fn(&SecurityEvent) + Send + Sync,
{
    fn handle(&self, event: &SecurityEvent) {
        (self.handler)(event);
    }
}

/// In-memory event store for testing and debugging.
#[derive(Clone)]
pub struct InMemoryEventStore {
    events: Arc<RwLock<Vec<SecurityEvent>>>,
    max_events: usize,
}

impl Default for InMemoryEventStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryEventStore {
    /// Create a new in-memory store.
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
            max_events: 10000,
        }
    }

    /// Set maximum events to keep.
    pub fn max_events(mut self, max: usize) -> Self {
        self.max_events = max;
        self
    }

    /// Get all stored events.
    pub async fn get_events(&self) -> Vec<SecurityEvent> {
        self.events.read().await.clone()
    }

    /// Get events filtered by type.
    pub async fn get_events_by_type(&self, event_type: &SecurityEventType) -> Vec<SecurityEvent> {
        self.events
            .read()
            .await
            .iter()
            .filter(|e| &e.event_type == event_type)
            .cloned()
            .collect()
    }

    /// Get events for a specific user.
    pub async fn get_events_by_user(&self, username: &str) -> Vec<SecurityEvent> {
        self.events
            .read()
            .await
            .iter()
            .filter(|e| e.username.as_deref() == Some(username))
            .cloned()
            .collect()
    }

    /// Clear all events.
    pub async fn clear(&self) {
        self.events.write().await.clear();
    }
}

impl SecurityEventHandler for InMemoryEventStore {
    fn handle(&self, event: &SecurityEvent) {
        // Use blocking lock for sync trait implementation
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            let events = Arc::clone(&self.events);
            let event = event.clone();
            let max = self.max_events;
            handle.spawn(async move {
                let mut guard = events.write().await;
                guard.push(event);
                if guard.len() > max {
                    guard.remove(0);
                }
            });
        }
    }
}

/// The main audit logger.
#[derive(Clone)]
pub struct AuditLogger {
    handlers: Arc<Vec<Arc<dyn SecurityEventHandler>>>,
    enabled: bool,
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLogger {
    /// Create a new audit logger with no handlers.
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(Vec::new()),
            enabled: true,
        }
    }

    /// Create an audit logger with stdout logging.
    pub fn with_stdout() -> Self {
        Self::new().add_handler(StdoutHandler::new())
    }

    /// Add an event handler.
    pub fn add_handler<H: SecurityEventHandler + 'static>(mut self, handler: H) -> Self {
        let handlers = Arc::make_mut(&mut self.handlers);
        handlers.push(Arc::new(handler));
        self
    }

    /// Add a closure as event handler.
    pub fn with_handler<F>(self, handler: F) -> Self
    where
        F: Fn(&SecurityEvent) + Send + Sync + 'static,
    {
        self.add_handler(ClosureHandler::new(handler))
    }

    /// Enable or disable the logger.
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Log a security event.
    pub fn log(&self, event: SecurityEvent) {
        if !self.enabled {
            return;
        }

        for handler in self.handlers.iter() {
            handler.handle(&event);
        }
    }

    /// Log a login success event.
    pub fn log_login_success(&self, username: &str, ip: &str) {
        self.log(SecurityEvent::login_success(username, ip));
    }

    /// Log a login failure event.
    pub fn log_login_failure(&self, username: &str, ip: &str, reason: &str) {
        self.log(SecurityEvent::login_failure(username, ip, reason));
    }

    /// Log an access denied event.
    pub fn log_access_denied(&self, username: &str, path: &str, ip: &str) {
        self.log(SecurityEvent::access_denied(username, path, ip));
    }

    /// Log a rate limit exceeded event.
    pub fn log_rate_limit_exceeded(&self, ip: &str, path: &str) {
        self.log(SecurityEvent::rate_limit_exceeded(ip, path));
    }
}

/// Global audit logger instance.
static GLOBAL_LOGGER: std::sync::OnceLock<AuditLogger> = std::sync::OnceLock::new();

/// Initialize the global audit logger.
pub fn init_global_logger(logger: AuditLogger) {
    let _ = GLOBAL_LOGGER.set(logger);
}

/// Get the global audit logger.
pub fn global_logger() -> &'static AuditLogger {
    GLOBAL_LOGGER.get_or_init(AuditLogger::new)
}

/// Log a security event using the global logger.
pub fn audit_log(event: SecurityEvent) {
    global_logger().log(event);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = SecurityEvent::login_success("admin", "192.168.1.1");
        assert_eq!(event.event_type, SecurityEventType::AuthenticationSuccess);
        assert_eq!(event.username, Some("admin".to_string()));
        assert_eq!(event.ip_address, Some("192.168.1.1".to_string()));
        assert_eq!(event.severity, SecurityEventSeverity::Info);
    }

    #[test]
    fn test_event_builder() {
        let event = SecurityEvent::new(SecurityEventType::AccessDenied)
            .username("user1")
            .ip_address("10.0.0.1")
            .path("/admin")
            .detail("reason", "missing role")
            .error("Access denied");

        assert_eq!(event.username, Some("user1".to_string()));
        assert_eq!(event.path, Some("/admin".to_string()));
        assert!(event.details.contains_key("reason"));
        assert_eq!(event.error, Some("Access denied".to_string()));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(SecurityEventSeverity::Info < SecurityEventSeverity::Warning);
        assert!(SecurityEventSeverity::Warning < SecurityEventSeverity::Error);
        assert!(SecurityEventSeverity::Error < SecurityEventSeverity::Critical);
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(
            SecurityEventType::AuthenticationSuccess.to_string(),
            "AUTHENTICATION_SUCCESS"
        );
        assert_eq!(
            SecurityEventType::Custom("test".to_string()).to_string(),
            "CUSTOM_TEST"
        );
    }

    #[test]
    fn test_log_line_format() {
        let event = SecurityEvent::login_failure("admin", "192.168.1.1", "Invalid password");
        let log_line = event.to_log_line();

        assert!(log_line.contains("[ERROR]"));
        assert!(log_line.contains("[AUTHENTICATION_FAILURE]"));
        assert!(log_line.contains("user=admin"));
        assert!(log_line.contains("ip=192.168.1.1"));
    }

    #[test]
    fn test_default_severity() {
        assert_eq!(
            SecurityEventType::AuthenticationSuccess.default_severity(),
            SecurityEventSeverity::Info
        );
        assert_eq!(
            SecurityEventType::BruteForceDetected.default_severity(),
            SecurityEventSeverity::Critical
        );
    }

    #[test]
    fn test_audit_logger_with_closure() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let logger = AuditLogger::new().with_handler(move |_event| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        logger.log_login_success("admin", "127.0.0.1");
        logger.log_login_failure("user", "127.0.0.1", "Bad password");

        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_disabled_logger() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let logger = AuditLogger::new()
            .with_handler(move |_event| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .enabled(false);

        logger.log_login_success("admin", "127.0.0.1");

        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }
}
