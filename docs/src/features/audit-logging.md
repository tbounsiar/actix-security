# Audit Logging

Audit logging captures security-relevant events for compliance, debugging, and threat detection.

## Enabling Audit Logging

Add the `audit` feature to your `Cargo.toml`:

```toml
[dependencies]
actix-security = { version = "0.2", features = ["audit"] }
```

## Basic Usage

```rust
use actix_security::http::security::{
    AuditLogger, SecurityEvent, SecurityEventType, StdoutHandler
};

// Create audit logger with stdout handler
let logger = AuditLogger::new()
    .add_handler(StdoutHandler::new());

// Log events
logger.log_login_success("admin", "192.168.1.1");
logger.log_login_failure("admin", "192.168.1.1", "Invalid password");
```

## Event Types

```rust
use actix_security::http::security::SecurityEventType;

// Authentication events
SecurityEventType::AuthenticationSuccess
SecurityEventType::AuthenticationFailure
SecurityEventType::Logout

// Session events
SecurityEventType::SessionCreated

// Authorization events
SecurityEventType::AccessGranted
SecurityEventType::AccessDenied

// Security events
SecurityEventType::AccountLocked
SecurityEventType::RateLimitExceeded
SecurityEventType::BruteForceDetected

// Custom events
SecurityEventType::Custom("password_changed".to_string())
```

## Event Severity

```rust
use actix_security::http::security::SecurityEventSeverity;

SecurityEventSeverity::Info      // Normal operations
SecurityEventSeverity::Warning   // Potential issues
SecurityEventSeverity::Error     // Failed operations
SecurityEventSeverity::Critical  // Security incidents
```

## Creating Events

```rust
use actix_security::http::security::SecurityEvent;

let event = SecurityEvent::new(SecurityEventType::AuthenticationFailure)
    .username("admin")
    .ip_address("192.168.1.1")
    .resource("/admin/dashboard")
    .error("Invalid credentials")
    .severity(SecurityEventSeverity::Warning)
    .add_detail("attempt_number", "3");

logger.log(event);
```

## Convenience Methods

```rust
// Login success
logger.log_login_success(&username, &ip);

// Login failure
logger.log_login_failure(&username, &ip, "Invalid password");

// Access denied
logger.log(
    SecurityEvent::new(SecurityEventType::AccessDenied)
        .username(&username)
        .resource("/admin")
        .ip_address(&ip)
);
```

## Event Handlers

### StdoutHandler

Prints events to standard output:

```rust
let handler = StdoutHandler::new();
```

### InMemoryEventStore

Stores events in memory (useful for testing):

```rust
use actix_security::http::security::InMemoryEventStore;

let store = InMemoryEventStore::new();
let logger = AuditLogger::new().add_handler(store.clone());

// Later, retrieve events
let events = store.get_events();
```

### Custom Handler

Implement the `SecurityEventHandler` trait:

```rust
use actix_security::http::security::{SecurityEventHandler, SecurityEvent};

struct DatabaseHandler {
    // database connection
}

impl SecurityEventHandler for DatabaseHandler {
    fn handle(&self, event: &SecurityEvent) {
        // Store in database
    }
}

let logger = AuditLogger::new()
    .add_handler(DatabaseHandler::new());
```

## Global Logger

Set up a global logger accessible from anywhere:

```rust
use actix_security::http::security::{init_global_logger, audit_log, global_logger};

// Initialize once at startup
init_global_logger(AuditLogger::new().add_handler(StdoutHandler::new()));

// Use anywhere
audit_log(SecurityEvent::new(SecurityEventType::AccessGranted)
    .username("admin")
    .resource("/api/users"));

// Or get the logger instance
if let Some(logger) = global_logger() {
    logger.log_login_success("admin", "127.0.0.1");
}
```

## JSON Output

Events can be serialized to JSON (enabled by default with the `audit` feature):

```json
{
  "event_type": "AuthenticationFailure",
  "severity": "Warning",
  "timestamp": "2024-01-15T10:30:00Z",
  "username": "admin",
  "ip_address": "192.168.1.1",
  "error": "Invalid credentials",
  "details": {
    "attempt_number": "3"
  }
}
```

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| `AuthenticationEventPublisher` | `AuditLogger` |
| `AbstractAuthenticationEvent` | `SecurityEvent` |
| `@EventListener` | `SecurityEventHandler` trait |
