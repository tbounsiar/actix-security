# Security Expression Language

Actix Security includes a powerful expression language inspired by Spring Security's SpEL (Spring Expression Language) for security.

## Overview

Security expressions allow you to write complex authorization rules in a readable, declarative syntax:

```rust
#[pre_authorize("hasRole('ADMIN') OR (hasRole('USER') AND hasAuthority('posts:write'))")]
```

## Key Features

- **Compile-time parsing** - Expressions are validated at compile time
- **Zero runtime overhead** - Expressions are compiled to Rust code
- **Extensible** - Add custom functions via `ExpressionRoot` trait
- **Familiar syntax** - Similar to Spring Security SpEL

## Expression Syntax

### Functions

| Function | Description | Example |
|----------|-------------|---------|
| `hasRole('R')` | User has role R | `hasRole('ADMIN')` |
| `hasAnyRole('R1', 'R2')` | User has any of the roles | `hasAnyRole('ADMIN', 'MANAGER')` |
| `hasAuthority('A')` | User has authority A | `hasAuthority('users:read')` |
| `hasAnyAuthority('A1', 'A2')` | User has any of the authorities | `hasAnyAuthority('read', 'write')` |
| `isAuthenticated()` | User is authenticated | `isAuthenticated()` |
| `permitAll()` | Always true | `permitAll()` |
| `denyAll()` | Always false | `denyAll()` |

### Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `AND` | Both must be true | `hasRole('A') AND hasRole('B')` |
| `OR` | Either can be true | `hasRole('A') OR hasRole('B')` |
| `NOT` | Negation | `NOT hasRole('GUEST')` |
| `( )` | Grouping | `(hasRole('A') OR hasRole('B')) AND hasAuthority('x')` |

## Examples

### Basic Expressions

```rust
// Single role check
#[pre_authorize("hasRole('ADMIN')")]

// Single authority check
#[pre_authorize("hasAuthority('posts:write')")]

// Any of multiple roles
#[pre_authorize("hasAnyRole('ADMIN', 'MANAGER', 'SUPERVISOR')")]

// Any of multiple authorities
#[pre_authorize("hasAnyAuthority('read', 'write', 'delete')")]

// Authenticated user
#[pre_authorize("isAuthenticated()")]
```

### Combining Conditions

```rust
// AND - both must be true
#[pre_authorize("hasRole('USER') AND hasAuthority('premium')")]

// OR - either can be true
#[pre_authorize("hasRole('ADMIN') OR hasAuthority('users:manage')")]

// NOT - negation
#[pre_authorize("NOT hasRole('GUEST')")]
#[pre_authorize("isAuthenticated() AND NOT hasRole('SUSPENDED')")]
```

### Complex Expressions

```rust
// Admin OR (User with write permission)
#[pre_authorize("hasRole('ADMIN') OR (hasRole('USER') AND hasAuthority('posts:write'))")]

// Multiple groups
#[pre_authorize("(hasRole('ADMIN') OR hasRole('MANAGER')) AND hasAuthority('reports:view')")]

// Nested conditions
#[pre_authorize("hasRole('ADMIN') OR (hasRole('USER') AND (hasAuthority('a') OR hasAuthority('b')))")]
```

## Compile-Time Validation

Expressions are parsed and validated at compile time:

```rust
// ✓ Valid
#[pre_authorize("hasRole('ADMIN') AND hasAuthority('write')")]

// ✗ Compile error: Use 'AND' not '&&'
#[pre_authorize("hasRole('ADMIN') && hasAuthority('write')")]

// ✗ Compile error: Unknown function
#[pre_authorize("hasPermission('admin')")]

// ✗ Compile error: Syntax error
#[pre_authorize("hasRole('ADMIN'")]
```

## How It Works

### 1. Parse at Compile Time

The expression is parsed into an AST:

```
hasRole('ADMIN') OR hasAuthority('write')
                 ↓
         Binary(OR)
        /         \
   hasRole      hasAuthority
   ('ADMIN')    ('write')
```

### 2. Generate Rust Code

The AST is compiled to Rust code:

```rust
// Expression: hasRole('ADMIN') OR hasAuthority('write')
// Generates:
user.has_role("ADMIN") || user.has_authority("write")
```

### 3. Execute at Runtime

The generated Rust code executes with zero parsing overhead.

## Spring Security Comparison

**Spring Security (Java):**
```java
@PreAuthorize("hasRole('ADMIN') or hasAuthority('users:write')")
public void updateUser() {}

@PreAuthorize("hasAnyRole('ADMIN', 'MANAGER') and hasAuthority('reports:view')")
public void viewReports() {}

@PreAuthorize("isAuthenticated() and !hasRole('GUEST')")
public void premiumContent() {}
```

**Actix Security (Rust):**
```rust
#[pre_authorize("hasRole('ADMIN') OR hasAuthority('users:write')")]
async fn update_user() {}

#[pre_authorize("hasAnyRole('ADMIN', 'MANAGER') AND hasAuthority('reports:view')")]
async fn view_reports() {}

#[pre_authorize("isAuthenticated() AND NOT hasRole('GUEST')")]
async fn premium_content() {}
```

Key differences:
- Use `AND`/`OR`/`NOT` instead of `and`/`or`/`!` (case-insensitive)
- Use single quotes for strings: `'ADMIN'` not `"ADMIN"`

## Sections

- [Built-in Functions](./builtin.md) - Detailed function reference
- [Custom Expressions](./custom.md) - Extend with your own functions
