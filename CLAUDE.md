# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Vision

**Goal**: Create a comprehensive security framework for Actix Web that mirrors Spring Security's functionality and developer experience. The framework should provide authentication, authorization, and security features through a combination of middleware, procedural macros (like Spring annotations), and a fluent configuration API.

**Target**: Make securing Actix Web applications as intuitive as Spring Security makes securing Spring applications.

## Build Commands

```bash
# Build the entire workspace
cargo build

# Build a specific crate
cargo build -p actix-security-core
cargo build -p actix-security-codegen

# Run tests (34 tests total)
cargo test

# Run a specific test
cargo test --package actix-security-core test_name

# Run the example application (http://127.0.0.1:8080)
cargo run -p actix-security-test

# Check for compilation errors
cargo check

# Format code
cargo fmt

# Run clippy lints
cargo clippy
```

## Architecture

### Workspace Structure

```
actix-security/
├── core/           # actix-security-core - Main library
├── codegen/        # actix-security-codegen - Procedural macros
├── test/           # actix-security-test - Example application + integration tests
└── docs/           # Documentation (ROADMAP.md, ARCHITECTURE.md)
```

### Core Design Pattern

The framework follows Spring Security's filter chain pattern adapted for Actix Web:

```
Request → SecurityTransform → SecurityService → [Authenticator] → [Authorizer] → Handler
```

### Key Traits (Extension Points)

1. **`Authenticator`** ([config.rs](core/src/http/security/config.rs)): Extract user identity from requests
   - Spring equivalent: `AuthenticationProvider`

2. **`Authorizer`** ([config.rs](core/src/http/security/config.rs)): Decide access based on user and request
   - Spring equivalent: `AccessDecisionManager`

3. **`PasswordEncoder`** ([crypto.rs](core/src/http/security/crypto.rs)): Hash and verify passwords
   - Spring equivalent: `PasswordEncoder`

### Current Implementations

| Component | Implementation | Spring Equivalent |
|-----------|---------------|-------------------|
| Authentication | `MemoryAuthenticator` | `InMemoryUserDetailsManager` |
| Authorization | `RequestMatcherAuthorizer` | `RequestMatcher` + `AuthorizationManager` |
| User Model | `User` with roles/authorities | `UserDetails` |
| Middleware | `SecurityTransform`/`SecurityService` | `SecurityFilterChain` |
| Password Hashing | `Argon2PasswordEncoder` | `Argon2PasswordEncoder` |
| HTTP Basic Auth | `HttpBasicConfig` | `httpBasic()` |
| Macros | `#[secured]`, `#[pre_authorize]` | `@Secured`, `@PreAuthorize` |

### User Model

`User` ([user.rs](core/src/http/security/user.rs)):
- `roles`: Coarse-grained access (e.g., "ADMIN", "USER") - Spring: `ROLE_*` authorities
- `authorities`: Fine-grained permissions - Spring: GrantedAuthority

Both use OR-matching: user needs at least ONE matching role OR authority.

## Current Status (v0.2.0)

### Completed
- ✅ Upgraded to Actix Web 4.x
- ✅ Fixed `login_url()` setter bug
- ✅ Updated all dependencies to latest versions
- ✅ Migrated procedural macros to syn 2.x
- ✅ Fixed middleware for Actix Web 4 Transform/Service traits
- ✅ Added `EitherBody` support for response types
- ✅ **HTTP Basic Authentication** (RFC 7617)
- ✅ **Argon2 Password Hashing** with `PasswordEncoder` trait
- ✅ **Spring Security-like macros**: `#[secured]`, `#[pre_authorize]`
- ✅ **Comprehensive integration tests** (25+ tests)

### Known Limitations
- No form login (only HTTP Basic)
- No JWT authentication
- No session management
- No CSRF/CORS protection

## Spring Security Feature Mapping

### Authentication (Spring → Actix Security)

| Spring Feature | Status | Notes |
|----------------|--------|-------|
| `InMemoryUserDetailsManager` | ✅ Working | `MemoryAuthenticator` |
| `JdbcUserDetailsManager` | ❌ Missing | Database authentication |
| Form Login | ❌ Missing | Only HTTP Basic Auth |
| HTTP Basic | ✅ Working | `RequestMatcherAuthorizer.http_basic()` |
| JWT Authentication | ❌ Missing | |
| OAuth2/OpenID Connect | ❌ Missing | |
| Remember Me | ❌ Missing | |
| Session Management | ❌ Missing | |
| Password Encoding | ✅ Working | `Argon2PasswordEncoder`, `DelegatingPasswordEncoder` |

### Authorization (Spring → Actix Security)

| Spring Feature | Status | Notes |
|----------------|--------|-------|
| URL-based (`antMatchers`) | ✅ Working | `RequestMatcherAuthorizer` with regex |
| `@PreAuthorize` | ✅ Working | `#[pre_authorize]` macro |
| `@Secured` | ✅ Working | `#[secured]` macro |
| `@RolesAllowed` | ❌ Missing | Use `#[secured]` instead |
| Method Security | ✅ Working | Via macros |
| Role Hierarchy | ❌ Missing | |

### Security Features (Spring → Actix Security)

| Spring Feature | Status | Notes |
|----------------|--------|-------|
| CSRF Protection | ❌ Missing | |
| CORS Configuration | ❌ Missing | |
| Security Headers | ❌ Missing | HSTS, CSP, X-Frame-Options |

## Coding Guidelines

### When Implementing New Features

1. **Follow Spring Security naming conventions** when possible for familiarity
2. **Use trait-based design** for extensibility (like Spring's interface-based design)
3. **Provide builder patterns** for configuration (fluent API)
4. **Write tests** for all security logic - security code must be well-tested
5. **Document security implications** in code comments
6. **Check [docs/ROADMAP.md](docs/ROADMAP.md)** for implementation priorities

### Macro Development (codegen crate)

- Macros should mirror Spring annotation behavior
- Provide clear compile-time error messages
- Support async functions properly
- Test macro expansion with `cargo expand`

### Error Handling

- Use `AuthError` enum for security-related errors
- Return appropriate HTTP status codes (401 Unauthorized, 403 Forbidden)
- Never leak sensitive information in error messages

## Testing the Application

```bash
cargo run -p actix-security-test
# Server runs at http://127.0.0.1:8080

# Test with curl (HTTP Basic Auth):
curl http://127.0.0.1:8080/login                                    # Public - login page
curl http://127.0.0.1:8080/                                         # 401 Unauthorized
curl -u admin:admin http://127.0.0.1:8080/                          # Home page
curl -u admin:admin http://127.0.0.1:8080/admin/dashboard           # Admin page (ADMIN role)
curl -u user:user http://127.0.0.1:8080/user/settings               # User page (USER role)
curl -u user:user http://127.0.0.1:8080/admin/dashboard             # 403 Forbidden
curl -u admin:admin http://127.0.0.1:8080/reports                   # @Secured("ADMIN")
curl -u admin:admin -X POST http://127.0.0.1:8080/api/users/create  # @PreAuthorize(authority)

# Test users (passwords hashed with Argon2):
# - admin/admin - Roles: [ADMIN, USER], Authorities: [users:read, users:write]
# - user/user   - Roles: [USER],        Authorities: [users:read]
# - guest/guest - Roles: [GUEST],       Authorities: []
```

## Macros Reference

### `#[secured("ROLE1", "ROLE2")]`
Spring equivalent: `@Secured({"ROLE_ADMIN", "ROLE_USER"})`

```rust
#[secured("ADMIN")]
#[get("/admin-only")]
async fn admin_only(user: AuthenticatedUser) -> impl Responder { }

#[secured("ADMIN", "MANAGER")]
#[get("/management")]
async fn management(user: AuthenticatedUser) -> impl Responder { }
```

### `#[pre_authorize(...)]`
Spring equivalent: `@PreAuthorize("...")`

```rust
// Require authentication only
#[pre_authorize(authenticated)]
async fn any_user() -> impl Responder { }

// Single role
#[pre_authorize(role = "ADMIN")]
async fn admin_role() -> impl Responder { }

// Multiple roles (OR)
#[pre_authorize(roles = ["ADMIN", "MANAGER"])]
async fn admin_or_manager() -> impl Responder { }

// Single authority
#[pre_authorize(authority = "users:write")]
async fn write_users() -> impl Responder { }

// Multiple authorities (OR)
#[pre_authorize(authorities = ["users:read", "users:write"])]
async fn read_or_write() -> impl Responder { }
```

## Dependencies

- `actix-web` 4.x
- `actix-service` 2.x
- `futures-util` 0.3.x
- `regex` for URL pattern matching
- `argon2` 0.5.x for password hashing
- `base64` 0.22.x for HTTP Basic Auth
- `syn` 2.x / `quote` / `proc-macro2` for procedural macros
- `derive_more` 1.x for error derive macros

## Documentation

- [ROADMAP.md](docs/ROADMAP.md) - Implementation plan and feature checklist
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) - Detailed architecture and Spring Security mapping
