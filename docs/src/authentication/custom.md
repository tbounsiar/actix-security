# Custom Authenticators

Create custom authenticators for database-backed user stores, OAuth, JWT, and more.

## Implementing the Authenticator Trait

```rust
use actix_security::http::security::config::Authenticator;
use actix_security::http::security::User;
use actix_web::dev::ServiceRequest;

#[derive(Clone)]
pub struct DatabaseAuthenticator {
    pool: sqlx::PgPool,  // Your database connection pool
}

impl Authenticator for DatabaseAuthenticator {
    fn authenticate(&self, req: &ServiceRequest) -> Option<User> {
        // 1. Extract credentials from request
        let auth_header = req.headers().get("Authorization")?;
        let (username, password) = parse_basic_auth(auth_header)?;

        // 2. Look up user in database
        // Note: This is sync, consider using block_on or async authenticator
        let user_record = self.find_user(&username)?;

        // 3. Verify password
        if !self.verify_password(&password, &user_record.password_hash) {
            return None;
        }

        // 4. Build and return User
        Some(User {
            username: user_record.username,
            password: user_record.password_hash,
            roles: user_record.roles.into_iter().collect(),
            authorities: user_record.authorities.into_iter().collect(),
        })
    }
}
```

## Example: JWT Authentication

```rust
use actix_security::http::security::config::Authenticator;
use actix_security::http::security::User;
use actix_web::dev::ServiceRequest;
use jsonwebtoken::{decode, DecodingKey, Validation};

#[derive(Clone)]
pub struct JwtAuthenticator {
    secret: String,
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,  // username
    roles: Vec<String>,
    authorities: Vec<String>,
    exp: usize,
}

impl Authenticator for JwtAuthenticator {
    fn authenticate(&self, req: &ServiceRequest) -> Option<User> {
        // Extract Bearer token
        let auth_header = req.headers().get("Authorization")?.to_str().ok()?;
        let token = auth_header.strip_prefix("Bearer ")?;

        // Decode and validate JWT
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &Validation::default(),
        ).ok()?;

        let claims = token_data.claims;

        // Build User from claims
        Some(User {
            username: claims.sub,
            password: String::new(),  // Not needed for JWT
            roles: claims.roles.into_iter().collect(),
            authorities: claims.authorities.into_iter().collect(),
        })
    }
}
```

## Example: API Key Authentication

```rust
use actix_security::http::security::config::Authenticator;
use actix_security::http::security::User;
use actix_web::dev::ServiceRequest;
use std::collections::HashMap;

#[derive(Clone)]
pub struct ApiKeyAuthenticator {
    api_keys: HashMap<String, User>,  // API key -> User
}

impl ApiKeyAuthenticator {
    pub fn new() -> Self {
        let mut api_keys = HashMap::new();

        // Register API keys
        api_keys.insert(
            "sk_live_abc123".to_string(),
            User::new("service_a".to_string(), String::new())
                .roles(&["SERVICE".into()])
                .authorities(&["api:read".into(), "api:write".into()]),
        );

        Self { api_keys }
    }
}

impl Authenticator for ApiKeyAuthenticator {
    fn authenticate(&self, req: &ServiceRequest) -> Option<User> {
        // Check X-API-Key header
        let api_key = req.headers()
            .get("X-API-Key")?
            .to_str()
            .ok()?;

        self.api_keys.get(api_key).cloned()
    }
}
```

## Example: Session-Based Authentication

```rust
use actix_security::http::security::config::Authenticator;
use actix_security::http::security::User;
use actix_session::SessionExt;
use actix_web::dev::ServiceRequest;

#[derive(Clone)]
pub struct SessionAuthenticator {
    user_service: UserService,  // Your user service
}

impl Authenticator for SessionAuthenticator {
    fn authenticate(&self, req: &ServiceRequest) -> Option<User> {
        // Get session
        let session = req.get_session();

        // Get user ID from session
        let user_id: i64 = session.get("user_id").ok()??;

        // Load user from database
        self.user_service.find_by_id(user_id)
    }
}
```

## Combining Multiple Authenticators

```rust
#[derive(Clone)]
pub struct CompositeAuthenticator {
    authenticators: Vec<Box<dyn Authenticator>>,
}

impl Authenticator for CompositeAuthenticator {
    fn authenticate(&self, req: &ServiceRequest) -> Option<User> {
        // Try each authenticator in order
        for auth in &self.authenticators {
            if let Some(user) = auth.authenticate(req) {
                return Some(user);
            }
        }
        None
    }
}

// Usage
let authenticator = CompositeAuthenticator {
    authenticators: vec![
        Box::new(JwtAuthenticator::new()),
        Box::new(ApiKeyAuthenticator::new()),
        Box::new(BasicAuthenticator::new()),
    ],
};
```

## Using with SecurityTransform

```rust
use actix_security::http::security::middleware::SecurityTransform;

let jwt_auth = JwtAuthenticator {
    secret: "your-secret-key".to_string(),
};

App::new()
    .wrap(
        SecurityTransform::new()
            .config_authenticator(move || jwt_auth.clone())
            .config_authorizer(|| {
                AuthorizationManager::request_matcher()
                    // No http_basic() needed for JWT
            })
    )
```

## Best Practices

### 1. Handle Errors Gracefully

```rust
fn authenticate(&self, req: &ServiceRequest) -> Option<User> {
    // Return None on any error - don't panic
    let header = req.headers().get("Authorization")?;
    let header_str = header.to_str().ok()?;  // Use ok()? for Result
    // ...
}
```

### 2. Use Constant-Time Comparison

```rust
use subtle::ConstantTimeEq;

fn verify_api_key(provided: &str, expected: &str) -> bool {
    provided.as_bytes().ct_eq(expected.as_bytes()).into()
}
```

### 3. Log Security Events

```rust
fn authenticate(&self, req: &ServiceRequest) -> Option<User> {
    let result = self.do_authenticate(req);

    match &result {
        Some(user) => log::info!("User {} authenticated", user.username),
        None => log::warn!("Authentication failed for request to {}", req.path()),
    }

    result
}
```

### 4. Rate Limit Authentication

Consider rate limiting authentication attempts to prevent brute force attacks.

## Spring Security Comparison

**Spring Security:**
```java
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        // Your authentication logic

        return new UsernamePasswordAuthenticationToken(
            username, password, authorities);
    }
}
```

**Actix Security:**
```rust
impl Authenticator for CustomAuthenticator {
    fn authenticate(&self, req: &ServiceRequest) -> Option<User> {
        // Your authentication logic
        Some(User { /* ... */ })
    }
}
```
