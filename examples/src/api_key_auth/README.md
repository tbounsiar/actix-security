# API Key Authentication Example

This example demonstrates API Key authentication for service-to-service communication and public APIs.

## Quick Start

Add these dependencies to your `Cargo.toml`:

```toml
[dependencies]
actix-web = "4"
actix-security = { version = "0.2", features = ["api-key"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Features

- API Key authentication from multiple locations (header, query, Authorization)
- In-memory API key repository
- Role and authority-based access control
- Key metadata, expiration, and enabled/disabled state

## Running the Example

```bash
# From the project root
cargo run --bin api_key_auth

# Or from the examples directory
cargo run -p actix-security-examples --bin api_key_auth
```

The server will start at `http://localhost:8080`.

## API Keys

| Key | Roles | Authorities |
|-----|-------|-------------|
| `sk_live_abc123` | API_USER | api:read |
| `sk_live_write_key` | API_USER | api:read, api:write |
| `sk_live_admin_key` | API_USER, ADMIN | api:read, api:write, api:admin |
| `sk_test_temp_key` | API_USER | api:read (expires in 24h) |
| `sk_disabled_key` | API_USER | - (disabled) |

## Endpoints

| Endpoint | Authorization | Description |
|----------|---------------|-------------|
| `/public` | None | Public endpoint |
| `/health` | None | Health check |
| `/api/data` | Role: API_USER | Protected API data |
| `/api/admin` | Role: ADMIN | Admin-only endpoint |
| `/api/me` | Role: API_USER | API key info |

## Testing

### Using curl

```bash
# Public endpoint (no auth needed)
curl http://127.0.0.1:8080/public

# With API key in header (recommended)
curl -H "X-API-Key: sk_live_abc123" http://127.0.0.1:8080/api/data

# With API key in Authorization header
curl -H "Authorization: ApiKey sk_live_abc123" http://127.0.0.1:8080/api/data

# With API key in query parameter
curl "http://127.0.0.1:8080/api/data?api_key=sk_live_abc123"

# Admin endpoint (requires ADMIN role)
curl -H "X-API-Key: sk_live_admin_key" http://127.0.0.1:8080/api/admin

# Regular key accessing admin (403 Forbidden)
curl -H "X-API-Key: sk_live_abc123" http://127.0.0.1:8080/api/admin

# Disabled key (401 Unauthorized)
curl -H "X-API-Key: sk_disabled_key" http://127.0.0.1:8080/api/data
```

## Code Overview

```rust
// Create API key repository
let repository = InMemoryApiKeyRepository::new()
    .with_key(ApiKey::new("sk_live_abc123")
        .name("Production Key")
        .roles(vec!["API_USER".into()])
        .authorities(vec!["api:read".into()]));

// Configure API key locations
let config = ApiKeyConfig::new()
    .add_location(ApiKeyLocation::header("X-API-Key"))
    .add_location(ApiKeyLocation::authorization("ApiKey"))
    .add_location(ApiKeyLocation::query("api_key"));

// Create authenticator
let authenticator = ApiKeyAuthenticator::new(repository).config(config);
```

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| Custom `AuthenticationFilter` | `ApiKeyAuthenticator` |
| `AuthenticationProvider` | `ApiKeyRepository` |
| `AbstractPreAuthenticatedProcessingFilter` | `ApiKeyLocation` |
| `UserDetails` | `ApiKey` model |

## Related Examples

- [HTTP Basic Authentication](../basic_auth/README.md) - Username/password auth
- [JWT Authentication](../jwt_auth/README.md) - Token-based authentication
- [WebSocket Authentication](../websocket_auth/README.md) - WebSocket security
