# Security Context

Access the current authenticated user from anywhere in your application.

## Overview

`SecurityContext` provides thread-safe access to the current user using Tokio's task-local storage. This is useful when you need to access user information outside of handlers.

## Basic Usage

```rust
use actix_security::http::security::SecurityContext;

// Get the current user
if let Some(user) = SecurityContext::get_user() {
    println!("Current user: {}", user.username);
}

// Check role
if SecurityContext::has_role("ADMIN") {
    // Admin-specific logic
}

// Check authority
if SecurityContext::has_authority("posts:write") {
    // Permission-specific logic
}
```

## API Reference

### get_user

Returns the current authenticated user, if any.

```rust
pub fn get_user() -> Option<User>
```

**Example:**
```rust
match SecurityContext::get_user() {
    Some(user) => println!("Logged in as: {}", user.username),
    None => println!("Not authenticated"),
}
```

### has_role

Checks if the current user has a specific role.

```rust
pub fn has_role(role: &str) -> bool
```

**Example:**
```rust
if SecurityContext::has_role("ADMIN") {
    // Show admin controls
}
```

### has_authority

Checks if the current user has a specific authority.

```rust
pub fn has_authority(authority: &str) -> bool
```

**Example:**
```rust
if SecurityContext::has_authority("posts:delete") {
    // Show delete button
}
```

### is_authenticated

Checks if there is an authenticated user.

```rust
pub fn is_authenticated() -> bool
```

**Example:**
```rust
if SecurityContext::is_authenticated() {
    // User is logged in
}
```

### run_with

Executes code with a specific user context.

```rust
pub async fn run_with<F, R>(user: Option<User>, f: F) -> R
where
    F: Future<Output = R>,
```

**Example:**
```rust
let user = User::new("test".to_string(), "".to_string())
    .roles(&["USER".into()]);

let result = SecurityContext::run_with(Some(user), async {
    // Code here has access to the user via SecurityContext
    SecurityContext::get_user()
}).await;
```

## Use Cases

### Service Layer Authorization

```rust
pub struct PostService;

impl PostService {
    pub async fn delete_post(&self, post_id: i64) -> Result<(), ServiceError> {
        // Check authorization in service layer
        let user = SecurityContext::get_user()
            .ok_or(ServiceError::Unauthorized)?;

        if !user.has_role("ADMIN") && !user.has_authority("posts:delete") {
            return Err(ServiceError::Forbidden);
        }

        // Proceed with deletion
        self.repository.delete(post_id).await
    }
}
```

### Audit Logging

```rust
pub fn log_action(action: &str, resource: &str) {
    let username = SecurityContext::get_user()
        .map(|u| u.username.clone())
        .unwrap_or_else(|| "anonymous".to_string());

    log::info!("AUDIT: {} performed {} on {}", username, action, resource);
}

// In handler
#[post("/posts")]
async fn create_post() -> impl Responder {
    log_action("CREATE", "post");
    // ...
}
```

### Dynamic Query Filtering

```rust
pub async fn get_visible_posts(&self) -> Vec<Post> {
    let user = SecurityContext::get_user();

    match user {
        Some(u) if u.has_role("ADMIN") => {
            // Admins see all posts
            self.repository.find_all().await
        }
        Some(u) => {
            // Users see their own posts + published posts
            self.repository.find_visible_for(&u.username).await
        }
        None => {
            // Anonymous users see only published posts
            self.repository.find_published().await
        }
    }
}
```

### Conditional UI Elements (in templates)

```rust
pub struct TemplateContext {
    pub can_edit: bool,
    pub can_delete: bool,
    pub is_admin: bool,
}

impl TemplateContext {
    pub fn from_security_context() -> Self {
        Self {
            can_edit: SecurityContext::has_authority("posts:write"),
            can_delete: SecurityContext::has_authority("posts:delete"),
            is_admin: SecurityContext::has_role("ADMIN"),
        }
    }
}
```

## How It Works

The security middleware sets up the context before handling each request:

```rust
// Simplified middleware flow
async fn call(&self, req: ServiceRequest) -> Result<ServiceResponse, Error> {
    // 1. Authenticate user
    let user = self.authenticator.authenticate(&req);

    // 2. Run handler with security context
    SecurityContext::run_with(user, async {
        // 3. Your handler runs here with access to SecurityContext
        self.service.call(req).await
    }).await
}
```

## Thread Safety

`SecurityContext` uses Tokio's `task_local!` macro, which provides:

- **Task isolation** - Each async task has its own context
- **Thread safety** - Safe to use across `.await` points
- **No data races** - Proper synchronization

```rust
// Safe to use across await points
async fn my_handler() {
    let user = SecurityContext::get_user();  // Before await

    some_async_operation().await;

    let same_user = SecurityContext::get_user();  // After await
    // Both return the same user
}
```

## Testing with Security Context

```rust
#[tokio::test]
async fn test_with_security_context() {
    let admin = User::new("admin".to_string(), "".to_string())
        .roles(&["ADMIN".into()]);

    SecurityContext::run_with(Some(admin), async {
        assert!(SecurityContext::is_authenticated());
        assert!(SecurityContext::has_role("ADMIN"));
        assert_eq!(SecurityContext::get_user().unwrap().username, "admin");
    }).await;
}

#[tokio::test]
async fn test_without_user() {
    SecurityContext::run_with(None, async {
        assert!(!SecurityContext::is_authenticated());
        assert!(!SecurityContext::has_role("ADMIN"));
        assert!(SecurityContext::get_user().is_none());
    }).await;
}
```

## Spring Security Comparison

**Spring Security:**
```java
// Get current user
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
String username = auth.getName();

// Check role
if (auth.getAuthorities().stream()
        .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
    // Admin logic
}

// Run with different context
SecurityContext context = SecurityContextHolder.createEmptyContext();
context.setAuthentication(newAuth);
SecurityContextHolder.setContext(context);
try {
    // Code runs with new context
} finally {
    SecurityContextHolder.clearContext();
}
```

**Actix Security:**
```rust
// Get current user
let user = SecurityContext::get_user();
let username = user.map(|u| u.username.clone());

// Check role
if SecurityContext::has_role("ADMIN") {
    // Admin logic
}

// Run with different context
SecurityContext::run_with(Some(new_user), async {
    // Code runs with new context
}).await;
```

## Limitations

1. **Request scope only** - Context is only available during request handling
2. **No cross-task sharing** - Each spawned task needs its own context
3. **Async only** - Uses Tokio's task-local storage

For spawned tasks, pass the user explicitly:

```rust
#[post("/process")]
async fn process(user: AuthenticatedUser) -> impl Responder {
    let user_clone = user.clone();

    tokio::spawn(async move {
        // SecurityContext not available here
        // Use user_clone directly
        process_in_background(user_clone).await;
    });

    HttpResponse::Accepted().body("Processing")
}
```
