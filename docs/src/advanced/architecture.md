# Architecture

Understanding Actix Security's internal architecture.

## Overview

Actix Security follows a **middleware-based architecture** inspired by Spring Security's filter chain. The security flow is:

```
Request → SecurityTransform → SecurityService → Your Handler → Response
              ↓                    ↓
         Authenticator         Authorizer
```

## Core Components

### SecurityTransform

The entry point for security. Implements Actix Web's `Transform` trait.

```rust
pub struct SecurityTransform<A, Z>
where
    A: Authenticator,
    Z: Authorizer,
{
    authenticator_factory: Box<dyn Fn() -> A>,
    authorizer_factory: Box<dyn Fn() -> Z>,
}
```

**Responsibilities:**
- Creates `SecurityService` for each worker
- Provides factory functions for authenticator and authorizer

### SecurityService

Wraps your service and applies security checks.

```rust
pub struct SecurityService<S, A, Z>
where
    A: Authenticator,
    Z: Authorizer,
{
    service: S,
    authenticator: A,
    authorizer: Z,
}
```

**Responsibilities:**
- Extracts user via authenticator
- Checks access via authorizer
- Sets up SecurityContext
- Calls your service if authorized

### Authenticator Trait

Defines how to extract user identity from requests.

```rust
pub trait Authenticator: Clone + Send + Sync + 'static {
    fn authenticate(&self, req: &ServiceRequest) -> Option<User>;
}
```

**Implementations:**
- `MemoryAuthenticator` - In-memory user store

### Authorizer Trait

Defines how to check access permissions.

```rust
pub trait Authorizer: Clone + Send + Sync + 'static {
    fn authorize(&self, user: Option<&User>, req: &ServiceRequest) -> AuthorizationResult;
}

pub enum AuthorizationResult {
    Granted,
    Denied,
    LoginRequired,
}
```

**Implementations:**
- `RequestMatcherAuthorizer` - URL pattern-based authorization

## Request Flow

```
1. Request arrives
   ↓
2. SecurityService.call() invoked
   ↓
3. Authenticator.authenticate()
   ├─ Success: User extracted
   └─ Failure: user = None
   ↓
4. Authorizer.authorize(user, request)
   ├─ Granted: Continue
   ├─ Denied: 403 Forbidden
   └─ LoginRequired: 401 or redirect
   ↓
5. SecurityContext.run_with(user, ...)
   ↓
6. Your handler executes
   ├─ Method security macros check
   └─ Handler code runs
   ↓
7. Response returned
```

## Module Structure

```
actix-security/          # Unified crate (recommended)
├── Cargo.toml          # Re-exports core + codegen
└── src/lib.rs          # Unified exports

core/                    # actix-security-core
├── http/
│   ├── error.rs         # AuthError type
│   └── security/
│       ├── mod.rs       # Public exports
│       ├── config.rs    # Traits (Authenticator, Authorizer)
│       ├── user.rs      # User model
│       ├── extractor.rs # AuthenticatedUser extractor
│       ├── context.rs   # SecurityContext
│       ├── middleware.rs# SecurityTransform, SecurityService
│       ├── authenticator/
│       │   └── memory.rs
│       ├── authorizer/
│       │   ├── access.rs
│       │   └── request_matcher.rs
│       ├── crypto/
│       │   ├── argon2.rs
│       │   ├── noop.rs
│       │   └── delegating.rs
│       ├── expression/
│       │   ├── ast.rs
│       │   ├── parser.rs
│       │   ├── evaluator.rs
│       │   └── root.rs
│       ├── headers.rs   # SecurityHeaders middleware
│       └── manager.rs   # Factory methods

codegen/                 # actix-security-codegen
├── lib.rs              # Macro exports
├── secured.rs          # #[secured] macro
├── pre_authorize.rs    # #[pre_authorize] macro
└── simple.rs           # permit_all, deny_all, roles_allowed
```

## Proc Macro Architecture

### Compile-Time Flow

```
#[pre_authorize("hasRole('ADMIN')")]
        ↓
    Parse expression (compile-time)
        ↓
    Build AST
        ↓
    Generate Rust code
        ↓
    Inject into handler
```

### Expression Compilation

```rust
// Input expression
"hasRole('ADMIN') OR hasAuthority('write')"

// Parsed AST
Binary {
    op: Or,
    left: Function("hasRole", ["ADMIN"]),
    right: Function("hasAuthority", ["write"]),
}

// Generated Rust
if !(user.has_role("ADMIN") || user.has_authority("write")) {
    return Err(AuthError::Forbidden);
}
```

## Thread Safety

All security components are designed to be thread-safe:

```rust
// All traits require these bounds
pub trait Authenticator: Clone + Send + Sync + 'static { }
pub trait Authorizer: Clone + Send + Sync + 'static { }
```

**SecurityContext** uses Tokio's task-local storage for safe async access:

```rust
tokio::task_local! {
    static SECURITY_CONTEXT: RefCell<Option<User>>;
}
```

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| `SecurityFilterChain` | `SecurityTransform` |
| `AuthenticationManager` | `Authenticator` trait |
| `AuthorizationManager` | `Authorizer` trait |
| `UserDetails` | `User` |
| `Authentication` | `AuthenticatedUser` |
| `SecurityContext` | `SecurityContext` |
| `MethodSecurityExpressionRoot` | `ExpressionRoot` trait |

## Extensibility Points

1. **Custom Authenticator** - Implement `Authenticator` trait
2. **Custom Authorizer** - Implement `Authorizer` trait
3. **Custom Password Encoder** - Implement `PasswordEncoder` trait
4. **Custom Expressions** - Implement `ExpressionRoot` trait

## Design Principles

1. **Compile-time safety** - Catch errors at compile time
2. **Zero-cost abstractions** - No runtime overhead for unused features
3. **Explicit over implicit** - Clear, readable security configuration
4. **Familiar API** - Similar to Spring Security for easy adoption
