# Roles vs Authorities

Understanding when to use roles versus authorities is key to designing a good security model.

## Quick Comparison

| Aspect | Roles | Authorities |
|--------|-------|-------------|
| Granularity | Coarse | Fine |
| Purpose | User categories | Specific permissions |
| Examples | ADMIN, USER, GUEST | users:read, posts:write |
| Use when | Grouping users | Controlling actions |

## Roles

Roles represent **what type of user** someone is.

### Characteristics
- Coarse-grained categories
- Usually few per application (3-10)
- Often hierarchical (ADMIN > MANAGER > USER)
- Represent job functions or user types

### Examples
```rust
User::with_encoded_password("john", encoded_password)
    .roles(&["USER".into()])

User::with_encoded_password("jane", encoded_password)
    .roles(&["ADMIN".into(), "USER".into()])

User::with_encoded_password("service", encoded_password)
    .roles(&["SERVICE".into()])
```

### Usage
```rust
// URL-based
.add_matcher("/admin/.*", Access::new().roles(vec!["ADMIN"]))

// Method-based
#[secured("ADMIN")]
#[get("/admin/dashboard")]
async fn admin_dashboard(user: AuthenticatedUser) -> impl Responder { /* ... */ }
```

## Authorities

Authorities represent **what actions** a user can perform.

### Characteristics
- Fine-grained permissions
- Many per application (10-100+)
- Usually flat (no hierarchy)
- Represent specific operations

### Naming Convention

Use `resource:action` format:

```
users:read     - Read user data
users:write    - Create/update users
users:delete   - Delete users
posts:read     - Read posts
posts:write    - Create/update posts
posts:publish  - Publish posts
admin:access   - Access admin area
reports:view   - View reports
reports:export - Export reports
```

### Examples
```rust
User::with_encoded_password("content_manager", encoded_password)
    .roles(&["USER".into()])
    .authorities(&[
        "posts:read".into(),
        "posts:write".into(),
        "posts:publish".into(),
    ])

User::with_encoded_password("analyst", encoded_password)
    .roles(&["USER".into()])
    .authorities(&[
        "reports:view".into(),
        "reports:export".into(),
    ])
```

### Usage
```rust
// URL-based
.add_matcher("/api/reports/.*", Access::new().authorities(vec!["reports:view"]))

// Method-based
#[pre_authorize(authority = "posts:publish")]
#[post("/posts/{id}/publish")]
async fn publish_post(user: AuthenticatedUser) -> impl Responder { /* ... */ }
```

## When to Use Each

### Use Roles When:

1. **Controlling broad sections of your app**
   ```rust
   .add_matcher("/admin/.*", Access::new().roles(vec!["ADMIN"]))
   ```

2. **User type matters more than specific permission**
   ```rust
   #[secured("PREMIUM")]
   #[get("/premium-content")]
   async fn premium_content() -> impl Responder { /* ... */ }
   ```

3. **Simple applications with clear user categories**

### Use Authorities When:

1. **Controlling specific operations**
   ```rust
   #[pre_authorize(authority = "users:delete")]
   #[delete("/users/{id}")]
   async fn delete_user() -> impl Responder { /* ... */ }
   ```

2. **Same role needs different capabilities**
   ```rust
   // Both are USERs, but with different permissions
   User::with_encoded_password("editor", pwd)
       .roles(&["USER".into()])
       .authorities(&["posts:write".into(), "posts:publish".into()])

   User::with_encoded_password("writer", pwd)
       .roles(&["USER".into()])
       .authorities(&["posts:write".into()])  // Can write but not publish
   ```

3. **Building permission-based features**
   ```rust
   // In handler, check specific permissions
   if user.has_authority("reports:export") {
       // Show export button
   }
   ```

## Combining Roles and Authorities

The most flexible approach uses both:

```rust
// Define users with roles AND authorities
User::with_encoded_password("admin", encoded_password)
    .roles(&["ADMIN".into()])
    .authorities(&[
        "users:read".into(),
        "users:write".into(),
        "users:delete".into(),
        "posts:read".into(),
        "posts:write".into(),
        "posts:delete".into(),
        "reports:view".into(),
        "reports:export".into(),
    ])

User::with_encoded_password("content_editor", encoded_password)
    .roles(&["USER".into()])
    .authorities(&[
        "posts:read".into(),
        "posts:write".into(),
    ])

// Use roles for broad access control
.add_matcher("/admin/.*", Access::new().roles(vec!["ADMIN"]))

// Use authorities for specific operations
#[pre_authorize(authority = "posts:publish")]
#[post("/posts/{id}/publish")]
async fn publish_post() -> impl Responder { /* ... */ }

// Combine in expressions
#[pre_authorize("hasRole('ADMIN') OR hasAuthority('posts:delete')")]
#[delete("/posts/{id}")]
async fn delete_post() -> impl Responder { /* ... */ }
```

## OR Logic

Both roles and authorities use **OR logic** - user needs **at least one** matching role OR authority:

```rust
// User needs ADMIN OR MANAGER (not both)
Access::new().roles(vec!["ADMIN", "MANAGER"])

// User needs users:read OR users:write (not both)
Access::new().authorities(vec!["users:read", "users:write"])
```

For **AND logic**, use expressions:

```rust
#[pre_authorize("hasRole('USER') AND hasAuthority('premium')")]
async fn premium_feature() -> impl Responder { /* ... */ }
```

## Spring Security Comparison

**Spring Security:**
```java
// Roles (Spring adds ROLE_ prefix internally)
@Secured("ROLE_ADMIN")
@PreAuthorize("hasRole('ADMIN')")

// Authorities (no prefix)
@PreAuthorize("hasAuthority('users:read')")
```

**Actix Security:**
```rust
// Roles (no prefix magic)
#[secured("ADMIN")]
#[pre_authorize("hasRole('ADMIN')")]

// Authorities
#[pre_authorize("hasAuthority('users:read')")]
```

> **Note**: Unlike Spring Security, Actix Security doesn't add any `ROLE_` prefix. Roles are stored exactly as you define them.

## Best Practices

1. **Use consistent naming**
   - Roles: UPPERCASE (ADMIN, USER, MANAGER)
   - Authorities: lowercase:action (users:read, posts:write)

2. **Don't over-engineer**
   - Start with roles only
   - Add authorities when you need finer control

3. **Document your permission model**
   ```rust
   // Document what each authority means
   /// users:read - View user list and profiles
   /// users:write - Create and update users
   /// users:delete - Delete users (admin only)
   ```

4. **Consider a permission matrix**
   | Role | users:read | users:write | users:delete |
   |------|-----------|-------------|--------------|
   | ADMIN | ✓ | ✓ | ✓ |
   | MANAGER | ✓ | ✓ | - |
   | USER | ✓ | - | - |
