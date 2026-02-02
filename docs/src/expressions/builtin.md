# Built-in Expression Functions

Reference for all built-in security expression functions.

## Role Functions

### hasRole

Checks if the user has a specific role.

```rust
#[pre_authorize("hasRole('ADMIN')")]
```

**Parameters:**
- `role` - The role name (string)

**Returns:** `true` if user has the role

**Example:**
```rust
#[pre_authorize("hasRole('ADMIN')")]
#[get("/admin")]
async fn admin(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Admin")
}
```

### hasAnyRole

Checks if the user has any of the specified roles.

```rust
#[pre_authorize("hasAnyRole('ADMIN', 'MANAGER', 'SUPERVISOR')")]
```

**Parameters:**
- `roles` - Variable number of role names

**Returns:** `true` if user has at least one of the roles

**Example:**
```rust
#[pre_authorize("hasAnyRole('ADMIN', 'MANAGER')")]
#[get("/management")]
async fn management(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Management")
}
```

## Authority Functions

### hasAuthority

Checks if the user has a specific authority.

```rust
#[pre_authorize("hasAuthority('users:write')")]
```

**Parameters:**
- `authority` - The authority name (string)

**Returns:** `true` if user has the authority

**Example:**
```rust
#[pre_authorize("hasAuthority('posts:write')")]
#[post("/posts")]
async fn create_post(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Created().body("Post created")
}
```

### hasAnyAuthority

Checks if the user has any of the specified authorities.

```rust
#[pre_authorize("hasAnyAuthority('read', 'write', 'admin')")]
```

**Parameters:**
- `authorities` - Variable number of authority names

**Returns:** `true` if user has at least one of the authorities

**Example:**
```rust
#[pre_authorize("hasAnyAuthority('posts:read', 'posts:write')")]
#[get("/posts")]
async fn list_posts(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Posts")
}
```

## Authentication Functions

### isAuthenticated

Checks if the user is authenticated.

```rust
#[pre_authorize("isAuthenticated()")]
```

**Parameters:** None

**Returns:** `true` if user is authenticated

**Example:**
```rust
#[pre_authorize("isAuthenticated()")]
#[get("/profile")]
async fn profile(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Hello, {}!", user.get_username()))
}
```

## Access Control Functions

### permitAll

Always returns true. Allows all access.

```rust
#[pre_authorize("permitAll()")]
```

**Parameters:** None

**Returns:** Always `true`

**Example:**
```rust
#[pre_authorize("permitAll()")]
#[get("/public")]
async fn public_info(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Public")
}
```

> **Note:** For public endpoints, consider using `#[permit_all]` macro instead, which doesn't require `AuthenticatedUser`.

### denyAll

Always returns false. Denies all access.

```rust
#[pre_authorize("denyAll()")]
```

**Parameters:** None

**Returns:** Always `false`

**Example:**
```rust
#[pre_authorize("denyAll()")]
#[get("/disabled")]
async fn disabled(_user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Never reached")
}
```

> **Note:** Consider using `#[deny_all]` macro instead for cleaner syntax.

## Function Reference Table

| Function | Parameters | Returns | Description |
|----------|------------|---------|-------------|
| `hasRole(role)` | 1 string | bool | User has role |
| `hasAnyRole(r1, r2, ...)` | 1+ strings | bool | User has any role |
| `hasAuthority(auth)` | 1 string | bool | User has authority |
| `hasAnyAuthority(a1, a2, ...)` | 1+ strings | bool | User has any authority |
| `isAuthenticated()` | none | bool | User is authenticated |
| `permitAll()` | none | bool | Always true |
| `denyAll()` | none | bool | Always false |

## Combining Functions

### With AND

Both conditions must be true:

```rust
#[pre_authorize("hasRole('USER') AND hasAuthority('premium')")]
```

### With OR

Either condition can be true:

```rust
#[pre_authorize("hasRole('ADMIN') OR hasAuthority('users:manage')")]
```

### With NOT

Negates a condition:

```rust
#[pre_authorize("NOT hasRole('GUEST')")]
#[pre_authorize("isAuthenticated() AND NOT hasRole('SUSPENDED')")]
```

### With Grouping

Use parentheses for complex logic:

```rust
#[pre_authorize("(hasRole('ADMIN') OR hasRole('MANAGER')) AND hasAuthority('reports:view')")]
```

## Case Sensitivity

- **Operators** are case-insensitive: `AND`, `and`, `And` all work
- **Function names** are case-sensitive: `hasRole` works, `HasRole` doesn't
- **Role/Authority names** are case-sensitive as stored in your user

## String Quoting

Use single quotes for string arguments:

```rust
// ✓ Correct
#[pre_authorize("hasRole('ADMIN')")]

// ✗ Wrong - double quotes cause parsing issues
#[pre_authorize("hasRole(\"ADMIN\")")]
```
