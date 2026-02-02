# Actix Security Examples

This directory contains runnable examples and integration tests demonstrating various features of actix-security.

## Directory Structure

```
examples/
├── src/
│   ├── lib.rs                  # Shared test utilities
│   ├── basic_auth/             # HTTP Basic authentication
│   │   ├── main.rs
│   │   └── README.md
│   ├── jwt_auth/               # JWT token authentication
│   │   ├── main.rs
│   │   └── README.md
│   ├── session_auth/           # Session-based authentication
│   │   ├── main.rs
│   │   └── README.md
│   ├── form_login/             # Form-based login with redirect
│   │   ├── main.rs
│   │   └── README.md
│   ├── security_headers/       # Security HTTP headers
│   │   ├── main.rs
│   │   └── README.md
│   ├── oidc_keycloak/          # OIDC with Keycloak
│   │   ├── main.rs
│   │   └── README.md
│   └── security_complete/      # All features combined
│       ├── main.rs
│       └── README.md
└── tests/
    ├── basic_auth_tests.rs
    ├── jwt_auth_tests.rs
    ├── session_auth_tests.rs
    ├── form_login_tests.rs
    ├── security_headers_tests.rs
    ├── rate_limit_tests.rs
    ├── account_lock_tests.rs
    └── audit_tests.rs
```

## Running Examples

```bash
# From the workspace root
cargo run -p actix-security-examples --bin <example_name>

# Or from the examples directory
cargo run --bin <example_name>

# Available examples
cargo run --bin basic_auth
cargo run --bin jwt_auth
cargo run --bin session_auth
cargo run --bin form_login
cargo run --bin security_headers
cargo run --bin oidc_keycloak
cargo run --bin security_complete
```

## Running Tests

```bash
# Run all integration tests
cargo test -p actix-security-examples

# Run a specific test file
cargo test -p actix-security-examples --test basic_auth_tests
cargo test -p actix-security-examples --test jwt_auth_tests
cargo test -p actix-security-examples --test session_auth_tests
cargo test -p actix-security-examples --test form_login_tests
cargo test -p actix-security-examples --test security_headers_tests
cargo test -p actix-security-examples --test rate_limit_tests
cargo test -p actix-security-examples --test account_lock_tests
cargo test -p actix-security-examples --test audit_tests

# Run with verbose output
cargo test -p actix-security-examples -- --nocapture
```

## Available Examples

| Example | Description | Features Used | Port |
|---------|-------------|---------------|------|
| [`basic_auth`](src/basic_auth/) | HTTP Basic authentication | `http-basic`, `argon2` | 8080 |
| [`jwt_auth`](src/jwt_auth/) | JWT token authentication with refresh | `jwt` | 8080 |
| [`session_auth`](src/session_auth/) | Session-based authentication | `session` | 8080 |
| [`form_login`](src/form_login/) | Form-based login with redirect | `form-login`, `csrf` | 8080 |
| [`security_headers`](src/security_headers/) | Security HTTP headers | (core) | 8080 |
| [`oidc_keycloak`](src/oidc_keycloak/) | OIDC with Keycloak | `oauth2` | 8080 |
| [`security_complete`](src/security_complete/) | All features combined | `full` | 8082 |

## Example Details

### basic_auth

Demonstrates HTTP Basic authentication with in-memory users and role-based access control.

```bash
cargo run --bin basic_auth

# Test
curl -u admin:admin http://localhost:8080/
curl -u admin:admin http://localhost:8080/admin
curl -u user:user http://localhost:8080/admin  # 403 Forbidden
```

See [basic_auth/README.md](src/basic_auth/README.md) for full details.

### jwt_auth

Shows JWT token generation, validation, and refresh token flow.

```bash
cargo run --bin jwt_auth

# Get token
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Use token
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/me
```

See [jwt_auth/README.md](src/jwt_auth/README.md) for full details.

### session_auth

Demonstrates session-based authentication with session fixation protection.

```bash
cargo run --bin session_auth

# Login (stores cookie)
curl -c cookies.txt -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Access protected resource
curl -b cookies.txt http://localhost:8080/dashboard
```

See [session_auth/README.md](src/session_auth/README.md) for full details.

### form_login

Browser-friendly form-based login with CSRF protection and redirect support.

```bash
cargo run --bin form_login

# Open in browser
open http://localhost:8080
```

See [form_login/README.md](src/form_login/README.md) for full details.

### security_headers

Demonstrates adding security headers (CSP, HSTS, X-Frame-Options, etc.).

```bash
cargo run --bin security_headers

# Check headers
curl -v http://localhost:8080/ 2>&1 | grep -E "^< "
```

See [security_headers/README.md](src/security_headers/README.md) for full details.

### oidc_keycloak

OIDC authentication with Keycloak identity provider.

```bash
# Prerequisites: Run Keycloak
docker run -p 8180:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev

# Set environment variables (see README for Keycloak setup)
export KEYCLOAK_URL=http://localhost:8180
export KEYCLOAK_REALM=actix-demo
export KEYCLOAK_CLIENT_ID=actix-app
export KEYCLOAK_CLIENT_SECRET=your-client-secret

cargo run --bin oidc_keycloak

# Open in browser
open http://localhost:8080
```

See [oidc_keycloak/README.md](src/oidc_keycloak/README.md) for full details.

### security_complete

Comprehensive example demonstrating all security features working together:
- Rate limiting (5 requests/minute)
- Account locking (3 failed attempts = 15 min lock)
- Audit logging (check console)
- Security headers
- Argon2 password hashing

```bash
cargo run --bin security_complete

# Open in browser
open http://localhost:8082

# Test rate limiting
for i in {1..6}; do curl http://localhost:8082/login -X POST -d "username=x&password=x"; done

# Test account locking (3 failures)
curl http://localhost:8082/login -X POST -d "username=admin&password=wrong"
curl http://localhost:8082/login -X POST -d "username=admin&password=wrong"
curl http://localhost:8082/login -X POST -d "username=admin&password=wrong"
# Now account is locked
```

See [security_complete/README.md](src/security_complete/README.md) for full details.

## Test Credentials

Most examples use these test accounts:

| Username | Password | Roles | Authorities |
|----------|----------|-------|-------------|
| admin | admin | ADMIN, USER | users:read, users:write |
| user | user | USER | users:read |
| guest | guest | GUEST | (none) |

## Shared Test Utilities

The `src/lib.rs` file provides shared test utilities:

```rust
use actix_security_examples::{TestUsers, credentials, server};

// Create standard test users
let users = TestUsers::new();
assert_eq!(users.admin.get_username(), "admin");

// Generate Basic auth header
let auth = credentials::basic_auth("admin", "admin");

// Assert response status
server::assert_ok(&response);
server::assert_unauthorized(&response);
server::assert_forbidden(&response);
```

## Dependencies

All examples share a single `Cargo.toml` with all required dependencies. The examples use the `full` feature of actix-security to have access to all features.

```toml
[dependencies]
actix-security = { path = "../actix-security", features = ["full"] }
actix-web = "4"
actix-session = { version = "0.10", features = ["cookie-session"] }
# ... more dependencies
```
