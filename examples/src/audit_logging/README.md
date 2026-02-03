# Audit Logging Example

This example demonstrates security audit logging with tracing integration.

## Quick Start

Add these dependencies to your `Cargo.toml`:

```toml
[dependencies]
actix-web = "4"
actix-security = { version = "0.2", features = ["audit", "http-basic", "argon2"] }
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Features

- Security event logging with multiple handlers
- Tracing integration for structured logging
- Custom event types and severity levels
- Automatic authentication and authorization logging

## Running the Example

```bash
# From the project root
cargo run --bin audit_logging

# Or from the examples directory
cargo run -p actix-security-examples --bin audit_logging
```

The server will start at `http://localhost:8080`.

## Endpoints

| Endpoint | Authorization | Description |
|----------|---------------|-------------|
| `/public` | None | Public endpoint |
| `/health` | None | Health check |
| `/api/data` | Role: USER | Protected API endpoint |
| `/admin` | Role: ADMIN | Admin-only endpoint |
| `/api/action` | Role: USER | Custom audit event |

## Test Users

| Username | Password | Roles |
|----------|----------|-------|
| admin | admin | ADMIN, USER |
| user | user | USER |

## Testing

Watch the console for security audit events:

```bash
# Public endpoint (no logging for auth)
curl http://127.0.0.1:8080/public

# Successful authentication (INFO log)
curl -u admin:admin http://127.0.0.1:8080/api/data

# Failed authentication (WARNING log)
curl -u admin:wrong http://127.0.0.1:8080/api/data

# Access denied (WARNING log)
curl -u user:user http://127.0.0.1:8080/admin

# Custom audit event
curl -u admin:admin http://127.0.0.1:8080/api/action
```

## Event Types

| Event Type | Severity | Description |
|------------|----------|-------------|
| `AUTHENTICATION_SUCCESS` | Info | User authenticated successfully |
| `AUTHENTICATION_FAILURE` | Warning | Authentication failed |
| `ACCESS_GRANTED` | Debug | User has required permissions |
| `ACCESS_DENIED` | Warning | User lacks required permissions |
| `Custom(...)` | Varies | Custom application events |

## Code Overview

```rust
// Initialize tracing subscriber
tracing_subscriber::fmt()
    .with_env_filter(
        EnvFilter::from_default_env()
            .add_directive("actix_security::audit=info".parse().unwrap())
    )
    .init();

// Create audit logger with handlers
let audit_logger = AuditLogger::new()
    .add_handler(TracingHandler::new())
    .add_handler(StdoutHandler::new());

// Log custom events
audit_logger.log(
    SecurityEvent::new(SecurityEventType::Custom("ACTION_PERFORMED".to_string()))
        .username(user.get_username())
        .path("/api/action")
        .detail("action", "data_export")
);
```

## Configuring Log Level

```bash
# Show all audit events (debug level)
RUST_LOG=actix_security::audit=debug cargo run --bin audit_logging

# Show only warnings and errors
RUST_LOG=actix_security::audit=warn cargo run --bin audit_logging
```

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| `AuthenticationEventPublisher` | `AuditLogger` |
| `AbstractAuthenticationEvent` | `SecurityEvent` |
| `@EventListener` | `SecurityEventHandler` trait |
| Spring AOP logging | `tracing` integration |

## Related Examples

- [HTTP Basic Authentication](../basic_auth/README.md) - Basic auth
- [Form Login](../form_login/README.md) - Form-based auth
- [Security Complete](../security_complete/README.md) - Full security setup
