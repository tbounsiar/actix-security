# Complete Security Example

This example demonstrates all major security features of actix-security working together.

## Quick Start

Add these dependencies to your `Cargo.toml`:

```toml
[dependencies]
actix-web = "4"
actix-security = { version = "0.2", features = ["full"] }
actix-session = { version = "0.10", features = ["cookie-session"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
log = "0.4"
env_logger = "0.11"
```

Or with only the specific features used:

```toml
[dependencies]
actix-web = "4"
actix-security = { version = "0.2", features = [
    "form-login",
    "csrf",
    "rate-limit",
    "account-lock",
    "audit",
    "argon2"
] }
actix-session = { version = "0.10", features = ["cookie-session"] }
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Features

- **Rate Limiting**: Brute-force protection (5 requests/minute)
- **Account Locking**: 3 failed attempts = 15 minute lock
- **Audit Logging**: Security events logged to console
- **Form Login**: HTML form-based authentication
- **CSRF Protection**: Cross-site request forgery protection
- **Password Encoding**: Argon2 password hashing
- **Security Headers**: X-Frame-Options, CSP, HSTS, etc.
- **Session Management**: Secure cookie-based sessions

## Running the Example

```bash
# From the project root
cargo run --bin security_complete

# Or from the examples directory
cargo run -p actix-security-examples --bin security_complete
```

The server will start at `http://localhost:8082`.

## Endpoints

| Endpoint | Method | Authorization | Description |
|----------|--------|---------------|-------------|
| `/` | GET | None | Home/Login page |
| `/login` | POST | None | Process login |
| `/logout` | POST | Authenticated | Logout |
| `/health` | GET | None | Health check (no rate limit) |

## Test Users

| Username | Password | Roles |
|----------|----------|-------|
| admin | admin | ADMIN, USER |
| user | user | USER |

## Security Features in Action

### 1. Rate Limiting

```bash
# Make 6 rapid requests - 6th will be blocked
for i in {1..6}; do
  curl -X POST http://localhost:8082/login \
    -d "username=admin&password=wrong" 2>/dev/null
  echo "Request $i"
done
# Output: Request 6 returns 429 Too Many Requests
```

### 2. Account Locking

```bash
# 3 failed login attempts lock the account
curl -X POST http://localhost:8082/login -d "username=admin&password=wrong1"
curl -X POST http://localhost:8082/login -d "username=admin&password=wrong2"
curl -X POST http://localhost:8082/login -d "username=admin&password=wrong3"
# Account is now locked for 15 minutes
curl -X POST http://localhost:8082/login -d "username=admin&password=admin"
# Returns: "Account is locked. Please try again later."
```

### 3. Audit Logging

Check console output for security events:

```
[INFO] SECURITY_EVENT: {
  "event_type": "AuthenticationSuccess",
  "severity": "Info",
  "username": "admin",
  "ip_address": "127.0.0.1",
  "timestamp": "2024-01-15T10:30:00Z"
}

[WARN] SECURITY_EVENT: {
  "event_type": "AuthenticationFailure",
  "severity": "Warning",
  "username": "admin",
  "ip_address": "127.0.0.1",
  "error": "Invalid credentials",
  "timestamp": "2024-01-15T10:30:05Z"
}

[ERROR] SECURITY_EVENT: {
  "event_type": "AccountLocked",
  "severity": "Error",
  "username": "admin",
  "ip_address": "127.0.0.1",
  "timestamp": "2024-01-15T10:30:10Z"
}
```

### 4. Security Headers

```bash
curl -I http://localhost:8082/
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# Content-Security-Policy: default-src 'self'
# Strict-Transport-Security: max-age=31536000; includeSubDomains
```

## Code Overview

```rust
// Password encoder
let encoder = Argon2PasswordEncoder::new();

// Create users with encoded passwords
let users = vec![
    User::with_encoded_password("admin", encoder.encode("admin"))
        .roles(&["ADMIN".into(), "USER".into()]),
    User::with_encoded_password("user", encoder.encode("user"))
        .roles(&["USER".into()]),
];

// Account lock manager (3 attempts, 15 min lock)
let lock_manager = AccountLockManager::new(
    LockConfig::new()
        .max_attempts(3)
        .lockout_duration(Duration::from_secs(15 * 60))
        .progressive_lockout(true),
);

// Audit logger
let audit_logger = AuditLogger::new()
    .add_handler(StdoutHandler::new());

// Rate limiter (5 requests/minute)
let rate_limiter = RateLimiter::new(
    RateLimitConfig::new()
        .requests_per_minute(5)
        .exclude_paths(vec!["/health"]),
);

// Security headers
let security_headers = SecurityHeaders::strict();

// Application setup
App::new()
    .wrap(security_headers)
    .wrap(rate_limiter)
    .wrap(SessionMiddleware::new(...))
    .app_data(web::Data::new(state))
```

## Testing with Browser

1. Open `http://localhost:8082`
2. You'll see the login form
3. Enter invalid credentials 3 times to trigger account lock
4. Wait 15 minutes or restart server to unlock
5. Login with valid credentials
6. Check console for audit logs

## Configuration Summary

| Feature | Configuration |
|---------|---------------|
| Rate Limit | 5 requests/minute |
| Account Lock | 3 attempts, 15 min lockout |
| Password Hash | Argon2 |
| Session Timeout | 30 minutes |
| HSTS Max Age | 1 year |

## Spring Security Equivalent

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .headers()
                .frameOptions().deny()
                .contentSecurityPolicy("default-src 'self'")
                .and()
                .httpStrictTransportSecurity()
                    .maxAgeInSeconds(31536000)
            .and()
            .sessionManagement()
                .sessionFixation().migrateSession()
            .and()
            .formLogin()
                .loginPage("/login")
                .defaultSuccessUrl("/")
            .and()
            .csrf();
    }

    @Bean
    public RateLimitingFilter rateLimitFilter() {
        return new RateLimitingFilter(5, Duration.ofMinutes(1));
    }

    @Bean
    public AccountLockingService accountLocking() {
        return new AccountLockingService(3, Duration.ofMinutes(15));
    }
}
```

## Related Examples

- [Basic Auth](../basic_auth/README.md) - HTTP Basic authentication
- [JWT Auth](../jwt_auth/README.md) - Token-based authentication
- [Session Auth](../session_auth/README.md) - Session management
- [Form Login](../form_login/README.md) - Form-based login
- [Security Headers](../security_headers/README.md) - Security headers
- [OIDC Keycloak](../oidc_keycloak/README.md) - OpenID Connect
