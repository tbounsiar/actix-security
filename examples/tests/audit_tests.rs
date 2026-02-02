//! Integration tests for security audit logging.

use actix_security::http::security::audit::{
    AuditLogger, SecurityEvent, SecurityEventSeverity, SecurityEventType, StdoutHandler,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[test]
fn test_event_creation() {
    let event = SecurityEvent::login_success("admin", "192.168.1.1");
    assert_eq!(event.event_type, SecurityEventType::AuthenticationSuccess);
    assert_eq!(event.username, Some("admin".to_string()));
    assert_eq!(event.ip_address, Some("192.168.1.1".to_string()));
    assert_eq!(event.severity, SecurityEventSeverity::Info);
}

#[test]
fn test_login_failure_event() {
    let event = SecurityEvent::login_failure("user", "10.0.0.1", "Invalid password");
    assert_eq!(event.event_type, SecurityEventType::AuthenticationFailure);
    assert_eq!(event.username, Some("user".to_string()));
    assert_eq!(event.error, Some("Invalid password".to_string()));
    assert_eq!(event.severity, SecurityEventSeverity::Error);
}

#[test]
fn test_access_denied_event() {
    let event = SecurityEvent::access_denied("user", "/admin", "192.168.1.1");
    assert_eq!(event.event_type, SecurityEventType::AccessDenied);
    assert_eq!(event.path, Some("/admin".to_string()));
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
        SecurityEventType::RateLimitExceeded.to_string(),
        "RATE_LIMIT_EXCEEDED"
    );
    assert_eq!(
        SecurityEventType::Custom("test".to_string()).to_string(),
        "CUSTOM_TEST"
    );
}

#[test]
fn test_default_severity() {
    assert_eq!(
        SecurityEventType::AuthenticationSuccess.default_severity(),
        SecurityEventSeverity::Info
    );
    assert_eq!(
        SecurityEventType::AuthenticationFailure.default_severity(),
        SecurityEventSeverity::Error
    );
    assert_eq!(
        SecurityEventType::BruteForceDetected.default_severity(),
        SecurityEventSeverity::Critical
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
fn test_event_to_json() {
    let event = SecurityEvent::login_success("admin", "192.168.1.1");
    let json = event.to_json();

    assert!(json.contains("\"event_type\":\"AUTHENTICATION_SUCCESS\""));
    assert!(json.contains("\"username\":\"admin\""));
    assert!(json.contains("\"ip_address\":\"192.168.1.1\""));
}

#[test]
fn test_audit_logger_with_closure() {
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

#[test]
fn test_rate_limit_event() {
    let event = SecurityEvent::rate_limit_exceeded("192.168.1.1", "/api/login");
    assert_eq!(event.event_type, SecurityEventType::RateLimitExceeded);
    assert_eq!(event.ip_address, Some("192.168.1.1".to_string()));
    assert_eq!(event.path, Some("/api/login".to_string()));
}

#[test]
fn test_account_locked_event() {
    let event = SecurityEvent::account_locked("user", "10.0.0.1", "Too many failed attempts");
    assert_eq!(event.event_type, SecurityEventType::AccountLocked);
    assert!(event.details.contains_key("reason"));
}

#[test]
fn test_brute_force_event() {
    let event = SecurityEvent::brute_force_detected("192.168.1.1", 100);
    assert_eq!(event.event_type, SecurityEventType::BruteForceDetected);
    assert_eq!(event.severity, SecurityEventSeverity::Critical);
    assert!(event.details.contains_key("attempts"));
}

#[test]
fn test_stdout_handler_creation() {
    let handler = StdoutHandler::new().min_severity(SecurityEventSeverity::Warning);
    // Just verify it compiles and can be created
    let _ = handler;
}

#[test]
fn test_custom_severity() {
    let event = SecurityEvent::new(SecurityEventType::AuthenticationSuccess)
        .severity(SecurityEventSeverity::Warning);

    // Override default severity
    assert_eq!(event.severity, SecurityEventSeverity::Warning);
}
