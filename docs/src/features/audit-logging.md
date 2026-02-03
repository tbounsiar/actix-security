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

### TracingHandler (Recommended)

Emits events through the `tracing` crate, integrating with the Rust ecosystem's standard observability infrastructure:

```rust
use actix_security::http::security::{AuditLogger, TracingHandler};
use tracing_subscriber;

// Initialize tracing subscriber (console output)
tracing_subscriber::fmt::init();

// Create audit logger with tracing handler
let logger = AuditLogger::new()
    .add_handler(TracingHandler::new());

// Events are emitted to target "actix_security::audit"
logger.log_login_success("admin", "192.168.1.1");
// Output: INFO actix_security::audit: Security event event_type="AUTHENTICATION_SUCCESS" user="admin" ip="192.168.1.1"
```

This handler automatically maps event severity to tracing levels:
- `Info` → `tracing::info!`
- `Warning` → `tracing::warn!`
- `Error`/`Critical` → `tracing::error!`

### StdoutHandler

Prints events to standard output (simpler, no tracing dependency):

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

Events can be serialized to JSON when serde is available (via `jwt`, `session`, or `oauth2` features):

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

## Automatic Tracing in Middleware

When the `audit` feature is enabled, the security middleware automatically emits tracing events for:

### Authentication Events
- `AUTHENTICATION_SUCCESS` - User authenticated successfully
- `AUTHENTICATION_ANONYMOUS` - Anonymous request (debug level)

### Authorization Events
- `ACCESS_GRANTED` - User has required permissions (debug level)
- `ACCESS_DENIED` - User lacks required permissions (warning level)
- `AUTHENTICATION_REQUIRED` - Redirecting to login or returning 401

Example output with `tracing-subscriber`:

```
INFO actix_security::audit: User authenticated successfully event_type="AUTHENTICATION_SUCCESS" user="admin" ip="192.168.1.1" path="/api/users" method="GET"
WARN actix_security::audit: Access denied: insufficient permissions event_type="ACCESS_DENIED" user="user1" path="/admin" required_roles=["ADMIN"]
```

### Filtering by Target

Use tracing's target filtering to control output:

```rust
use tracing_subscriber::EnvFilter;

tracing_subscriber::fmt()
    .with_env_filter(
        EnvFilter::from_default_env()
            // Show all security audit events
            .add_directive("actix_security::audit=info".parse().unwrap())
    )
    .init();
```

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| `AuthenticationEventPublisher` | `AuditLogger` |
| `AbstractAuthenticationEvent` | `SecurityEvent` |
| `@EventListener` | `SecurityEventHandler` trait |
| Spring AOP logging | `tracing` integration |
