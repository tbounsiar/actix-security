# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **API Key Authentication** (`api-key` feature)
  - Support for header, query parameter, and Authorization header extraction
  - `ApiKeyAuthenticator` implementing the `Authenticator` trait
  - `ApiKeyRepository` trait for custom storage backends
  - `InMemoryApiKeyRepository` for development and testing
  - `ApiKey` model with roles, authorities, expiration, and metadata
  - Multiple extraction locations with configurable priority
  - Key validation (enabled status, expiration)
  - Example application demonstrating API key authentication

- **WebSocket Security** (`websocket` feature)
  - Origin validation for Cross-Site WebSocket Hijacking (CSWSH) prevention
  - `OriginValidator` with pattern matching and wildcard support
  - `WebSocketSecurityConfig` for unified security configuration
  - `WebSocketUser` and `WebSocketUpgrade` extractors
  - JWT authentication during WebSocket handshake
  - Role and authority checks for WebSocket connections
  - Example application demonstrating WebSocket security patterns

## [0.2.2] - 2026-02-02

### Added
- **Custom Expressions with Parameter References** - Spring Security-style `#param` syntax
  - Reference handler parameters directly in `#[pre_authorize]` expressions
  - Support for `Path<T>`, `Query<T>`, `Json<T>`, and `Form<T>` extractors
  - Custom async authorization functions with signature `async fn(user: &User, ...) -> bool`
  - Combine custom functions with built-in expressions using AND/OR operators

- **Rust-style Expression Syntax** - snake_case functions and Rust operators
  - Snake_case function aliases: `has_role`, `has_any_role`, `has_authority`, `has_any_authority`, `is_authenticated`, `permit_all`, `deny_all`
  - Rust operators: `&&` (AND), `||` (OR), `!` (NOT)
  - Both Spring style (camelCase, AND/OR/NOT) and Rust style work interchangeably

- **Simplified Dependency** - Users now only need `actix-security` as a dependency
  - Macros automatically detect whether `actix-security` or `actix-security-core` is used
  - No need to add `actix-security-core` as a separate dependency

### Examples
```rust
// Define custom authorization function
pub async fn is_tenant_admin(user: &User, tenant_id: i64) -> bool {
    user.has_authority(&format!("tenant:{}:admin", tenant_id))
}

// Use with parameter reference
#[pre_authorize("is_tenant_admin(#tenant_id)")]
#[get("/tenants/{tenant_id}")]
async fn get_tenant(tenant_id: Path<i64>, user: AuthenticatedUser) -> impl Responder { }

// Combine with built-in functions
#[pre_authorize("hasRole('ADMIN') OR is_tenant_admin(#tenant_id)")]
#[get("/tenants/{tenant_id}/settings")]
async fn get_settings(tenant_id: Path<i64>, user: AuthenticatedUser) -> impl Responder { }
```

## [0.2.1] - 2026-02-02

### Fixed
- Correct minimum supported Rust version (MSRV) to 1.78 for Cargo.lock v4 compatibility
- Fix clippy warning: use `std::io::Error::other()` instead of deprecated pattern
- Fix rustdoc warning: escape generic type in documentation comments
- Fix GitHub Actions workflow using correct `dtolnay/rust-toolchain` action

### Changed
- Add versioned documentation support with version selector
- Remove generated `docs/book` from version control

## [0.2.0] - 2026-02-02

### Added

#### Authentication
- **LDAP Authentication** (`ldap` feature)
  - Full LDAP/Active Directory authentication support
  - Configurable user search filters and base DN
  - Group-to-role mapping
  - Active Directory preset configuration
  - MockLdapClient for testing

- **SAML 2.0 Authentication** (`saml` feature)
  - Complete SAML 2.0 Service Provider implementation
  - AuthnRequest generation and Response parsing
  - Assertion validation (audience, timing, signature)
  - Preset configurations for Okta, Azure AD, Google Workspace, ADFS
  - SP metadata generation
  - Single Logout (SLO) support

- **OAuth2/OIDC Authentication** (`oauth2` feature)
  - OAuth2 authorization code flow
  - OpenID Connect support
  - Provider presets (Google, GitHub, Microsoft, Keycloak, Okta)
  - Token refresh
  - User info endpoint

- **Session Authentication** (`session` feature)
  - Server-side session management
  - Session fixation protection (MigrateSession, NewSession, None)
  - Configurable session timeout
  - SessionLoginService for login/logout

- **Form Login** (`form-login` feature)
  - HTML form-based authentication
  - Success/failure URL redirects
  - Remember saved request for post-login redirect

- **Remember-Me** (`remember-me` feature)
  - Persistent login tokens
  - Configurable validity period
  - Secure token generation

- **CSRF Protection** (`csrf` feature)
  - Token-based CSRF protection
  - Session-backed token repository
  - Configurable ignored paths and methods

- **JWT Authentication** (`jwt` feature)
  - Enhanced JWT support with refresh tokens
  - RSA key support (RS256, RS384, RS512)
  - Custom claims extraction
  - Token pair generation

#### Security Features
- **Rate Limiting** (`rate-limit` feature)
  - Multiple algorithms: Fixed Window, Sliding Window, Token Bucket
  - Per-IP, per-user, or custom key extraction
  - Configurable exclusion paths
  - Rate limit headers in response

- **Account Locking** (`account-lock` feature)
  - Automatic lockout after failed attempts
  - Progressive lockout delays
  - IP address tracking
  - Manual unlock capability
  - Permanent lock support

- **Audit Logging** (`audit` feature)
  - Security event logging
  - Multiple severity levels (Info, Warning, Error, Critical)
  - JSON serialization support
  - Pluggable event handlers
  - Built-in StdoutHandler and InMemoryEventStore

- **Channel Security** (always available)
  - HTTPS enforcement middleware
  - Path-based channel requirements
  - Configurable port mapping
  - Redirect status code options

#### Utilities
- **AntMatcher** (always available)
  - Spring-style URL pattern matching
  - Wildcards: `?`, `*`, `**`
  - Path variable extraction (`{id}`)
  - Case-insensitive matching option

- **BCrypt Password Encoder** (`bcrypt` feature)
  - BCrypt password hashing support
  - Compatible with existing BCrypt hashes
  - Configurable cost parameter

- **UserDetailsService** (`user-details` feature)
  - Async trait for loading users
  - UserDetailsManager for CRUD operations
  - CachingUserDetailsService wrapper
  - InMemoryUserDetailsService implementation

### Changed
- Minimum Rust version is now 1.78
- Updated all dependencies to latest versions
- Improved error messages and documentation
- Reorganized module structure

### Fixed
- Various clippy warnings resolved
- Documentation typos corrected

## [0.1.0] - 2026-02-02

### Added
- Initial release
- HTTP Basic authentication
- In-memory user store
- Role and authority-based access control
- Security expression language
- `#[secured]` and `#[pre_authorize]` macros
- `#[permit_all]` and `#[deny_all]` macros
- URL-based authorization with regex patterns
- Argon2 password encoding
- Security headers middleware
- Security context for accessing current user

[Unreleased]: https://github.com/tbounsiar/actix-security/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/tbounsiar/actix-security/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/tbounsiar/actix-security/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/tbounsiar/actix-security/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tbounsiar/actix-security/releases/tag/v0.1.0
