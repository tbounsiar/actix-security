# Custom Expressions Example

This example demonstrates Spring Security-style custom expressions with parameter references (`#param` syntax) in `#[pre_authorize]`.

## Quick Start

Add these dependencies to your `Cargo.toml`:

```toml
[dependencies]
actix-web = "4"
actix-security = { version = "0.2", features = ["macros", "argon2"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Features

- Custom authorization functions
- Parameter references (`#tenant_id`, `#query`, `#body`)
- Combined expressions (`hasRole('ADMIN') || is_tenant_admin(#id)`)
- Path, query, and JSON body parameter extraction
- Rust-style expression syntax

## Running the Example

```bash
# From the project root
cargo run --bin custom_expressions

# Or from the examples directory
cargo run -p actix-security-examples --bin custom_expressions
```

The server will start at `http://localhost:8080`.

## Test Users

| Username | Password | Roles | Tenant ID |
|----------|----------|-------|-----------|
| admin | admin | ADMIN | - |
| user | user | USER | 1 |

## Endpoints and Access Rules

| Endpoint | Rule | Description |
|----------|------|-------------|
| `/tenants/{id}` | `is_tenant_admin(#id)` | Tenant access |
| `/tenants/{id}/settings` | `hasRole('ADMIN') \|\| is_tenant_admin(#id)` | Tenant settings |
| `/resources/{name}` | `can_access_resource(#name)` | Resource access |
| `/products/search?min_price=X` | `can_search_with_price(#query)` | Search filtering |
| `POST /orders` | `can_create_order(#body)` | Order creation |

## Testing

### Tenant Access

```bash
# Admin can access any tenant
curl -u admin:admin http://localhost:8080/tenants/123

# User can only access their own tenant (ID: 1)
curl -u user:user http://localhost:8080/tenants/1       # OK
curl -u user:user http://localhost:8080/tenants/2       # 403 Forbidden
```

### Combined Expressions

```bash
# Admin can access any tenant settings (hasRole)
curl -u admin:admin http://localhost:8080/tenants/999/settings

# User can access their tenant settings (is_tenant_admin)
curl -u user:user http://localhost:8080/tenants/1/settings      # OK
curl -u user:user http://localhost:8080/tenants/2/settings      # 403
```

### Query Parameter Extraction

```bash
# User can search with low prices
curl -u user:user "http://localhost:8080/products/search?min_price=50"

# High price search requires premium (403)
curl -u user:user "http://localhost:8080/products/search?min_price=500"
```

### JSON Body Extraction

```bash
# User can create orders up to $1000
curl -u user:user -X POST http://localhost:8080/orders \
     -H "Content-Type: application/json" \
     -d '{"amount": 100}'   # OK

# Large orders require ADMIN role
curl -u user:user -X POST http://localhost:8080/orders \
     -H "Content-Type: application/json" \
     -d '{"amount": 5000}'  # 403 Forbidden
```

## Code Overview

### Custom Authorization Function

```rust
/// Custom authorization function for tenant access
fn is_tenant_admin(user: &User, tenant_id: &str) -> bool {
    // Admin can access any tenant
    if user.has_role("ADMIN") {
        return true;
    }
    // Users can only access their assigned tenant
    user.get_metadata("tenant_id") == Some(&tenant_id.to_string())
}
```

### Using in Handler

```rust
#[pre_authorize(is_tenant_admin(#tenant_id))]
#[get("/tenants/{tenant_id}")]
async fn get_tenant(
    user: AuthenticatedUser,
    tenant_id: web::Path<String>,
) -> impl Responder {
    // Handler code
}
```

### Combined Expressions

```rust
#[pre_authorize(hasRole('ADMIN') || is_tenant_admin(#tenant_id))]
#[get("/tenants/{tenant_id}/settings")]
async fn get_tenant_settings(...) -> impl Responder {
    // Handler code
}
```

## Parameter Reference Syntax

| Syntax | Source | Example |
|--------|--------|---------|
| `#path_param` | Path parameter | `#tenant_id` from `/{tenant_id}` |
| `#query` | Query struct | `#query.min_price` |
| `#body` | JSON body | `#body.amount` |

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| `@PreAuthorize("hasRole('ADMIN')")` | `#[pre_authorize(hasRole('ADMIN'))]` |
| `@PreAuthorize("#id == principal.id")` | `#[pre_authorize(is_owner(#id))]` |
| SpEL expressions | Rust-style expressions |
| `SecurityExpressionRoot` | Custom functions |

## Related Examples

- [HTTP Basic Authentication](../basic_auth/README.md) - Basic auth
- [Security Complete](../security_complete/README.md) - Full security setup
- [Audit Logging](../audit_logging/README.md) - Security events
