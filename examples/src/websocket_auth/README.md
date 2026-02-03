# WebSocket Authentication Example

This example demonstrates WebSocket security with JWT authentication and CSWSH prevention.

## Quick Start

Add these dependencies to your `Cargo.toml`:

```toml
[dependencies]
actix-web = "4"
actix-ws = "0.3"
actix-security = { version = "0.2", features = ["websocket", "jwt"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Features

- JWT authentication during WebSocket handshake
- Origin validation (CSWSH prevention)
- Role and authority checks
- User context available in WebSocket connection
- Browser test page included

## Running the Example

```bash
# From the project root
cargo run --bin websocket_auth

# Or from the examples directory
cargo run -p actix-security-examples --bin websocket_auth
```

The server will start at `http://localhost:8080`.

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API documentation |
| `/login` | POST | Get JWT token |
| `/ws` | WebSocket | Secure WebSocket (auth + origin) |
| `/ws/config` | WebSocket | WebSocketSecurityConfig example |
| `/ws/public` | WebSocket | Public WebSocket (origin check only) |
| `/test` | GET | Browser test page |

## Test Users

| Username | Password | Roles | Authorities |
|----------|----------|-------|-------------|
| admin | admin | ADMIN, USER | ws:connect, ws:admin |
| user | user | USER | ws:connect |

## Testing

### Using websocat

```bash
# Install websocat
cargo install websocat

# Get JWT token
TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.token')

# Connect to secure WebSocket
websocat "ws://localhost:8080/ws" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Origin: http://localhost:8080"

# Connect to public WebSocket
websocat "ws://localhost:8080/ws/public" \
  -H "Origin: http://localhost:8080"
```

### Using a Browser

1. Open http://localhost:8080/test
2. Click "Login" to get a JWT token
3. Click "Connect to /ws/public" (browsers can't set custom headers)
4. Send messages and observe the responses

## Security Features

### CSWSH Prevention

Cross-Site WebSocket Hijacking is prevented by validating the Origin header:

```rust
let origin_validator = OriginValidator::builder()
    .allow("http://localhost:8080")
    .allow("http://127.0.0.1:8080")
    .allow_localhost_in_dev(true)
    .build();
```

### JWT Validation

The server validates JWT tokens in the Authorization header:

```rust
let auth_header = req.headers().get("Authorization");
let token = auth_header.and_then(|h| h.strip_prefix("Bearer "));
let user = jwt_authenticator.validate_token(token)?;
```

### Authority Checks

WebSocket connections can require specific authorities:

```rust
if !user.has_authority("ws:connect") {
    return Err(ErrorForbidden("Missing ws:connect authority"));
}
```

## Code Overview

```rust
// Origin validator for CSWSH prevention
let origin_validator = OriginValidator::builder()
    .allow("http://localhost:8080")
    .allow_localhost_in_dev(true)
    .build();

// WebSocket security configuration
let ws_config = WebSocketSecurityConfig::new()
    .allowed_origins(vec!["http://localhost:8080".into()])
    .require_authentication(true)
    .required_authorities(vec!["ws:connect".into()]);

// In handler
#[get("/ws")]
async fn ws_handler(req: HttpRequest, stream: Payload) -> Result<HttpResponse, Error> {
    origin_validator.validate(&req)?;  // CSWSH check
    let user = extract_jwt_user(&req)?;  // Auth check
    // ... upgrade to WebSocket
}
```

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| `WebSocketSecurityConfigurer` | `WebSocketSecurityConfig` |
| `AbstractSecurityWebSocketMessageBrokerConfigurer` | Security middleware + `OriginValidator` |
| `@PreAuthorize` on message handlers | Manual checks in handler |
| CORS/Origin checking | `OriginValidator` |

## Related Examples

- [JWT Authentication](../jwt_auth/README.md) - JWT token-based auth
- [Session Authentication](../session_auth/README.md) - Cookie-based sessions
- [API Key Authentication](../api_key_auth/README.md) - Service-to-service auth
