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
- **Parameter references** - Reference handler parameters with `#param_name` syntax
- **Custom functions** - Define async authorization functions with any logic
- **Dual syntax support** - Both Spring Security style (camelCase) and Rust style (snake_case)

## Expression Syntax

### Functions

Both camelCase (Spring Security style) and snake_case (Rust style) are supported:

| Spring Style | Rust Style | Description |
|--------------|------------|-------------|
| `hasRole('R')` | `has_role('R')` | User has role R |
| `hasAnyRole('R1', 'R2')` | `has_any_role('R1', 'R2')` | User has any of the roles |
| `hasAuthority('A')` | `has_authority('A')` | User has authority A |
| `hasAnyAuthority('A1', 'A2')` | `has_any_authority('A1', 'A2')` | User has any of the authorities |
| `isAuthenticated()` | `is_authenticated()` | User is authenticated |
| `permitAll()` | `permit_all()` | Always true |
| `denyAll()` | `deny_all()` | Always false |

### Operators

Both Spring Security style and Rust style operators are supported:

| Spring Style | Rust Style | Description |
|--------------|------------|-------------|
| `AND` | `&&` | Both must be true |
| `OR` | `\|\|` | Either can be true |
| `NOT` | `!` | Negation |
| `( )` | `( )` | Grouping |

**Note:** Operators are case-insensitive (`AND`, `and`, `And` all work).

## Examples

### Basic Expressions

```rust
// Single role check (both styles work)
#[pre_authorize("hasRole('ADMIN')")]
#[pre_authorize("has_role('ADMIN')")]

// Single authority check
#[pre_authorize("hasAuthority('posts:write')")]
#[pre_authorize("has_authority('posts:write')")]

// Any of multiple roles
#[pre_authorize("hasAnyRole('ADMIN', 'MANAGER', 'SUPERVISOR')")]
#[pre_authorize("has_any_role('ADMIN', 'MANAGER', 'SUPERVISOR')")]

// Any of multiple authorities
#[pre_authorize("hasAnyAuthority('read', 'write', 'delete')")]
#[pre_authorize("has_any_authority('read', 'write', 'delete')")]

// Authenticated user
#[pre_authorize("isAuthenticated()")]
```

### Combining Conditions

```rust
// AND - both must be true (Spring style)
#[pre_authorize("hasRole('USER') AND hasAuthority('premium')")]
// Rust style
#[pre_authorize("has_role('USER') && has_authority('premium')")]

// OR - either can be true (Spring style)
#[pre_authorize("hasRole('ADMIN') OR hasAuthority('users:manage')")]
// Rust style
#[pre_authorize("has_role('ADMIN') || has_authority('users:manage')")]

// NOT - negation (Spring style)
#[pre_authorize("NOT hasRole('GUEST')")]
// Rust style
#[pre_authorize("!has_role('GUEST')")]
```

### Complex Expressions

```rust
// Admin OR (User with write permission) - Spring style
#[pre_authorize("hasRole('ADMIN') OR (hasRole('USER') AND hasAuthority('posts:write'))")]
// Rust style
#[pre_authorize("has_role('ADMIN') || (has_role('USER') && has_authority('posts:write'))")]

// Mixed styles also work!
#[pre_authorize("hasRole('ADMIN') || has_role('USER') && has_authority('write')")]

// Complex nested conditions
#[pre_authorize("has_role('ADMIN') || (has_role('USER') && (has_authority('a') || has_authority('b')))")]
```

## Compile-Time Validation

Expressions are parsed and validated at compile time:

```rust
// ✓ Valid - built-in function
#[pre_authorize("hasRole('ADMIN') AND hasAuthority('write')")]

// ✓ Valid - custom function with parameter reference (v0.2.2+)
#[pre_authorize("is_tenant_admin(#tenant_id)")]

// ✓ Valid - combining built-in and custom functions
#[pre_authorize("hasRole('ADMIN') OR my_custom_check(#resource_id)")]

// ✗ Compile error: Unknown parameter reference
#[pre_authorize("my_check(#nonexistent_param)")]

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

**Actix Security (Rust) - Spring style:**
```rust
#[pre_authorize("hasRole('ADMIN') OR hasAuthority('users:write')")]
async fn update_user() {}

#[pre_authorize("hasAnyRole('ADMIN', 'MANAGER') AND hasAuthority('reports:view')")]
async fn view_reports() {}

#[pre_authorize("isAuthenticated() AND NOT hasRole('GUEST')")]
async fn premium_content() {}
```

**Actix Security (Rust) - Rust style:**
```rust
#[pre_authorize("has_role('ADMIN') || has_authority('users:write')")]
async fn update_user() {}

#[pre_authorize("has_any_role('ADMIN', 'MANAGER') && has_authority('reports:view')")]
async fn view_reports() {}

#[pre_authorize("is_authenticated() && !has_role('GUEST')")]
async fn premium_content() {}
```

**Syntax flexibility:**
- Both camelCase and snake_case function names work
- Both `AND`/`OR`/`NOT` and `&&`/`||`/`!` operators work
- Operators are case-insensitive (`AND`, `and`, `And` all work)
- Use single quotes for strings: `'ADMIN'` not `"ADMIN"`

## Sections

- [Built-in Functions](./builtin.md) - Detailed function reference
- [Custom Expressions](./custom.md) - Extend with your own functions
