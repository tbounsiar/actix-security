# URL-Based Authorization

Configure access rules for URL patterns using `RequestMatcherAuthorizer`.

## Basic Usage

```rust
use actix_security::http::security::{AuthorizationManager, Access};

let authorizer = AuthorizationManager::request_matcher()
    .login_url("/login")
    .http_basic()
    .add_matcher("/admin/.*", Access::new().roles(vec!["ADMIN"]))
    .add_matcher("/api/.*", Access::new().authenticated())
    .add_matcher("/user/.*", Access::new().roles(vec!["USER", "ADMIN"]));
```

## URL Patterns

Patterns use **regex** syntax:

| Pattern | Matches |
|---------|---------|
| `/admin/.*` | `/admin/`, `/admin/users`, `/admin/settings/security` |
| `/api/v[0-9]+/.*` | `/api/v1/users`, `/api/v2/posts` |
| `/user/[^/]+/profile` | `/user/john/profile`, `/user/123/profile` |
| `.*\\.json` | Any URL ending in `.json` |

## Access Rules

### Role-Based Access

```rust
// Single role
Access::new().roles(vec!["ADMIN"])

// Multiple roles (OR logic - any role grants access)
Access::new().roles(vec!["ADMIN", "MANAGER", "SUPERVISOR"])
```

### Authority-Based Access

```rust
// Single authority
Access::new().authorities(vec!["users:read"])

// Multiple authorities (OR logic)
Access::new().authorities(vec!["users:read", "users:write"])
```

### Combined Rules

```rust
// Require role AND authority
Access::new()
    .roles(vec!["USER"])
    .authorities(vec!["premium:access"])
```

### Authentication Only

```rust
// Any authenticated user
Access::new().authenticated()
```

### Deny All

```rust
// Block all access (useful for deprecated endpoints)
Access::new().deny_all()
```

## Pattern Order

Patterns are matched in the order they're added. First match wins.

```rust
AuthorizationManager::request_matcher()
    .add_matcher("/admin/public/.*", Access::new().authenticated())  // First
    .add_matcher("/admin/.*", Access::new().roles(vec!["ADMIN"]))    // Second
```

With this configuration:
- `/admin/public/info` → Any authenticated user
- `/admin/users` → Only ADMIN role

## Complete Example

```rust
use actix_web::{get, web, App, HttpServer, HttpResponse, Responder};
use actix_security::http::security::{
    AuthenticatedUser, AuthenticationManager, AuthorizationManager,
    Argon2PasswordEncoder, PasswordEncoder, User, Access,
};
use actix_security::http::security::middleware::SecurityTransform;

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Home - Public")
}

#[get("/admin/dashboard")]
async fn admin_dashboard(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Admin: {}", user.get_username()))
}

#[get("/api/users")]
async fn api_users(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().json(vec!["user1", "user2"])
}

#[get("/user/profile")]
async fn user_profile(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Profile: {}", user.get_username()))
}

fn create_authorizer() -> RequestMatcherAuthorizer {
    AuthorizationManager::request_matcher()
        .login_url("/login")
        .http_basic()
        // Public paths (no matcher = public)
        // Admin section
        .add_matcher("/admin/.*", Access::new().roles(vec!["ADMIN"]))
        // API requires authentication + specific authority
        .add_matcher("/api/.*", Access::new().authorities(vec!["api:access"]))
        // User section
        .add_matcher("/user/.*", Access::new().roles(vec!["USER", "ADMIN"]))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let encoder = Argon2PasswordEncoder::new();

    HttpServer::new(move || {
        let enc = encoder.clone();
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(move || {
                        AuthenticationManager::in_memory_authentication()
                            .password_encoder(enc.clone())
                            .with_user(
                                User::with_encoded_password("admin", enc.encode("admin"))
                                    .roles(&["ADMIN".into()])
                                    .authorities(&["api:access".into()])
                            )
                            .with_user(
                                User::with_encoded_password("user", enc.encode("user"))
                                    .roles(&["USER".into()])
                            )
                    })
                    .config_authorizer(create_authorizer)
            )
            .service(index)
            .service(admin_dashboard)
            .service(api_users)
            .service(user_profile)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Testing URL Authorization

```bash
# Public - no auth needed
curl http://127.0.0.1:8080/
# Output: Home - Public

# Admin section - requires ADMIN role
curl -u admin:admin http://127.0.0.1:8080/admin/dashboard
# Output: Admin: admin

curl -u user:user http://127.0.0.1:8080/admin/dashboard
# Output: 403 Forbidden

# API - requires api:access authority
curl -u admin:admin http://127.0.0.1:8080/api/users
# Output: ["user1","user2"]

curl -u user:user http://127.0.0.1:8080/api/users
# Output: 403 Forbidden (user doesn't have api:access)

# User section - requires USER or ADMIN role
curl -u user:user http://127.0.0.1:8080/user/profile
# Output: Profile: user
```

## Spring Security Comparison

**Spring Security:**
```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/admin/**").hasRole("ADMIN")
    .requestMatchers("/api/**").hasAuthority("api:access")
    .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
    .anyRequest().permitAll()
);
```

**Actix Security:**
```rust
AuthorizationManager::request_matcher()
    .add_matcher("/admin/.*", Access::new().roles(vec!["ADMIN"]))
    .add_matcher("/api/.*", Access::new().authorities(vec!["api:access"]))
    .add_matcher("/user/.*", Access::new().roles(vec!["USER", "ADMIN"]))
    // No matcher = permit all
```

## Best Practices

1. **Order patterns from specific to general**
2. **Use method security for complex rules** - URL patterns are best for simple role checks
3. **Don't over-complicate patterns** - Keep regex simple and readable
4. **Document your security rules** - Complex patterns can be hard to maintain
