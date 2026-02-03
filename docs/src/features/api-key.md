# API Key Authentication

API Key authentication is a simple authentication method where clients include a pre-shared key in their requests. It's commonly used for:

- Service-to-service communication
- Public APIs with usage tracking
- Simple authentication without user sessions

## Feature Flag

Enable API Key authentication by adding the `api-key` feature:

```toml
[dependencies]
actix-security = { version = "0.2", features = ["api-key"] }
```

## Key Locations

API keys can be extracted from multiple locations:

| Location | Example | Description |
|----------|---------|-------------|
| Header | `X-API-Key: sk_live_abc123` | Recommended - most secure |
| Authorization Header | `Authorization: ApiKey sk_live_abc123` | Uses custom scheme |
| Query Parameter | `?api_key=sk_live_abc123` | Less secure, for testing |

## Basic Setup

```rust
use actix_security::http::security::api_key::{
    ApiKeyAuthenticator, InMemoryApiKeyRepository, ApiKeyConfig, ApiKey,
};
use actix_security::http::security::middleware::SecurityTransform;

// Create API key repository
let repository = InMemoryApiKeyRepository::new()
    .with_key(ApiKey::new("sk_live_abc123")
        .name("Production Key")
        .roles(vec!["API_USER".into()])
        .authorities(vec!["api:read".into(), "api:write".into()]));

// Create authenticator
let authenticator = ApiKeyAuthenticator::new(repository);

// Use with middleware
App::new()
    .wrap(SecurityTransform::new()
        .config_authenticator(move || authenticator.clone()))
```

## Configuration Options

### Custom Header Name

```rust
let config = ApiKeyConfig::header("X-Custom-API-Key");
let authenticator = ApiKeyAuthenticator::new(repository).config(config);
```

### Authorization Header with Custom Scheme

```rust
// Expects: Authorization: Bearer sk_live_abc123
let config = ApiKeyConfig::authorization("Bearer");
```

### Query Parameter

```rust
// Reads from ?api_key=... or ?token=...
let config = ApiKeyConfig::query("api_key");
```

### Multiple Locations

Check multiple locations in order of priority:

```rust
use actix_security::http::security::api_key::ApiKeyLocation;

let config = ApiKeyConfig::new()
    .add_location(ApiKeyLocation::header("X-API-Key"))        // Check first
    .add_location(ApiKeyLocation::authorization("ApiKey"))    // Then this
    .add_location(ApiKeyLocation::query("api_key"));          // Finally this
```

## API Key Model

The `ApiKey` struct holds all metadata for a key:

```rust
let key = ApiKey::new("sk_live_abc123")
    .name("Production API Key")                     // Human-readable name
    .owner("service@example.com")                   // Owner identifier
    .roles(vec!["API_USER".into(), "ADMIN".into()]) // Roles for authorization
    .authorities(vec!["api:read".into()])           // Fine-grained permissions
    .enabled(true)                                  // Enable/disable the key
    .expires_in(Duration::from_secs(86400 * 365))   // Set expiration
    .with_metadata("environment", "production");    // Custom metadata
```

### Builder Pattern

For more complex key creation:

```rust
let key = ApiKey::builder("sk_live_abc123")
    .name("My Key")
    .role("USER")                // Add single role
    .role("ADMIN")               // Add another role
    .authority("api:read")       // Add single authority
    .authority("api:write")      // Add another authority
    .metadata("tier", "premium") // Add metadata
    .build();
```

## Custom Repository

Implement `ApiKeyRepository` for custom storage backends:

```rust
use actix_security::http::security::api_key::{ApiKey, ApiKeyRepository};

struct DatabaseApiKeyRepository {
    pool: DbPool,
}

impl ApiKeyRepository for DatabaseApiKeyRepository {
    fn find_by_key(&self, key: &str) -> Option<ApiKey> {
        // Query your database
        let row = self.pool.query_one(
            "SELECT * FROM api_keys WHERE key_value = $1 AND enabled = true",
            &[&key]
        ).ok()?;

        Some(ApiKey::new(row.get("key_value"))
            .name(row.get("name"))
            .owner(row.get("owner"))
            .roles(row.get::<_, Vec<String>>("roles"))
            .authorities(row.get::<_, Vec<String>>("authorities"))
            .enabled(row.get("enabled")))
    }
}
```

## Validation Options

Control what validations are performed:

```rust
let config = ApiKeyConfig::default()
    .validate_expiration(true)   // Check if key has expired (default: true)
    .validate_enabled(true);     // Check if key is enabled (default: true)
```

## Complete Example

See the full example in the repository:

```bash
cargo run -p actix-security-examples --bin api_key_auth
```

```rust
use actix_security::http::security::api_key::{
    ApiKey, ApiKeyAuthenticator, ApiKeyConfig, ApiKeyLocation, InMemoryApiKeyRepository,
};
use actix_security::http::security::middleware::SecurityTransform;
use actix_security::http::security::web::{Access, RequestMatcherAuthorizer};
use actix_security::http::security::{AuthenticatedUser, AuthorizationManager};

fn authenticator() -> ApiKeyAuthenticator<InMemoryApiKeyRepository> {
    let repository = InMemoryApiKeyRepository::new()
        .with_key(ApiKey::new("sk_live_abc123")
            .name("Production Key")
            .roles(vec!["API_USER".into()])
            .authorities(vec!["api:read".into()]));

    ApiKeyAuthenticator::new(repository).config(
        ApiKeyConfig::new()
            .add_location(ApiKeyLocation::header("X-API-Key"))
            .add_location(ApiKeyLocation::authorization("ApiKey"))
            .add_location(ApiKeyLocation::query("api_key")),
    )
}

fn authorizer() -> RequestMatcherAuthorizer {
    AuthorizationManager::request_matcher()
        .add_matcher("/api/admin.*", Access::new().roles(vec!["ADMIN"]))
        .add_matcher("/api/.*", Access::new().roles(vec!["API_USER"]))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(move || {
        App::new()
            .wrap(SecurityTransform::new()
                .config_authenticator(authenticator)
                .config_authorizer(authorizer))
            .service(api_endpoint)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Testing

```bash
# Without API key
curl http://127.0.0.1:8080/api/data
# -> Redirects to /login

# With API key in header
curl -H "X-API-Key: sk_live_abc123" http://127.0.0.1:8080/api/data
# -> 200 OK

# With API key in Authorization header
curl -H "Authorization: ApiKey sk_live_abc123" http://127.0.0.1:8080/api/data
# -> 200 OK

# With API key in query parameter
curl "http://127.0.0.1:8080/api/data?api_key=sk_live_abc123"
# -> 200 OK
```

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| Custom `AuthenticationFilter` | `ApiKeyAuthenticator` |
| `AuthenticationProvider` | `ApiKeyRepository` |
| `AbstractPreAuthenticatedProcessingFilter` | `ApiKeyConfig` locations |
| `UserDetails` | `ApiKey` model |

## Security Best Practices

1. **Use HTTPS** - API keys are transmitted in plaintext
2. **Prefer Header Location** - Query parameters may be logged
3. **Rotate Keys Regularly** - Implement key rotation policies
4. **Limit Scope** - Use roles/authorities to restrict key capabilities
5. **Set Expiration** - Don't use keys that never expire
6. **Monitor Usage** - Log API key usage for security auditing
7. **Rate Limit** - Prevent abuse with rate limiting per key
