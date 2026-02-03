# WebSocket Security

Secure your WebSocket connections with authentication and origin validation.

## Overview

WebSocket security works by securing the HTTP upgrade request before the connection is established:

```text
Client                    Server
  |                          |
  |--HTTP Upgrade Request--->|
  |  (with auth token)       | 1. Validate origin (CSWSH prevention)
  |                          | 2. Authenticate user
  |                          | 3. Check roles/authorities
  |<--101 Switching----------|
  |                          |
  |==WebSocket Connection====| User available in connection
  |                          |
```

## Enable Feature

```toml
[dependencies]
actix-security = { version = "0.2", features = ["websocket", "jwt"] }
actix-ws = "0.3"
```

## Cross-Site WebSocket Hijacking (CSWSH) Prevention

CSWSH is an attack where a malicious website establishes a WebSocket connection using the victim's browser cookies:

```javascript
// On evil.com - this includes victim's cookies automatically!
const ws = new WebSocket('wss://yourapp.com/ws');
```

**Solution**: Validate the `Origin` header.

### OriginValidator

```rust
use actix_security::http::security::websocket::OriginValidator;

// Simple configuration
let validator = OriginValidator::new(&["https://myapp.com"]);

// Builder pattern with more options
let validator = OriginValidator::builder()
    .allow("https://myapp.com")
    .allow("https://admin.myapp.com")
    .allow_subdomain_pattern("*.myapp.com")  // Matches api.myapp.com, etc.
    .allow_localhost_in_dev(true)  // Only in debug builds
    .build();

// Use in handler
#[get("/ws")]
async fn ws_handler(req: HttpRequest) -> Result<HttpResponse, Error> {
    validator.validate(&req)?;  // Returns 403 if origin invalid
    // ... upgrade to WebSocket
}
```

## WebSocket Security Configuration

For comprehensive security, use `WebSocketSecurityConfig`:

```rust
use actix_security::http::security::websocket::WebSocketSecurityConfig;

let ws_config = WebSocketSecurityConfig::new()
    .allowed_origins(vec!["https://myapp.com".into()])
    .require_authentication(true)
    .required_roles(vec!["USER".into()])
    .required_authorities(vec!["ws:connect".into()]);

#[get("/ws")]
async fn ws_handler(
    req: HttpRequest,
    stream: web::Payload,
    config: web::Data<WebSocketSecurityConfig>,
) -> Result<HttpResponse, Error> {
    // Validates origin, auth, roles, and authorities in one call
    let upgrade = config.validate_upgrade(&req)?;

    // Get the authenticated user
    let user = upgrade.into_user().expect("User is present");

    // Upgrade to WebSocket
    let (response, session, msg_stream) = actix_ws::handle(&req, stream)?;
    // ... spawn handler with user
    Ok(response)
}
```

## JWT Authentication for WebSocket

Since browsers can't send custom headers with WebSocket, use JWT in the Authorization header:

```rust
use actix_security::http::security::{
    JwtAuthenticator, JwtConfig,
    websocket::OriginValidator,
};

fn extract_user_from_jwt(
    req: &HttpRequest,
    jwt_auth: &JwtAuthenticator,
) -> Result<User, String> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => return Err("Missing Authorization header".into()),
    };

    jwt_auth.validate_token(token)
        .map(|data| User::new(data.claims.sub, String::new())
            .roles(&data.claims.roles)
            .authorities(&data.claims.authorities))
        .map_err(|e| format!("Invalid token: {}", e))
}

#[get("/ws")]
async fn ws_handler(
    req: HttpRequest,
    stream: web::Payload,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    // 1. Validate origin
    data.origin_validator.validate(&req)?;

    // 2. Authenticate via JWT
    let user = extract_user_from_jwt(&req, &data.jwt_authenticator)
        .map_err(actix_web::error::ErrorUnauthorized)?;

    // 3. Check authority
    if !user.has_authority("ws:connect") {
        return Err(actix_web::error::ErrorForbidden("Missing ws:connect authority"));
    }

    // 4. Upgrade to WebSocket
    let (response, mut session, mut msg_stream) = actix_ws::handle(&req, stream)?;

    actix_web::rt::spawn(async move {
        while let Some(Ok(msg)) = msg_stream.next().await {
            match msg {
                Message::Text(text) => {
                    // Access user in message handler
                    if user.has_role("ADMIN") && text.trim() == "admin-cmd" {
                        let _ = session.text("Admin command executed").await;
                    } else {
                        let _ = session.text(format!("[{}] {}", user.get_username(), text)).await;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    Ok(response)
}
```

## WebSocketUser Extractor

For simpler extraction with role/authority checks:

```rust
use actix_security::http::security::websocket::WebSocketUser;

#[get("/ws")]
async fn ws_handler(req: HttpRequest, stream: web::Payload) -> Result<HttpResponse, Error> {
    // Extract and validate in one line
    let user = WebSocketUser::extract(&req)?
        .require_role("USER")?       // Check role
        .require_authority("ws:connect")?  // Check authority
        .into_inner();

    // ... upgrade to WebSocket with user
}
```

## Client-Side Usage

### JavaScript (Browser)

```javascript
// Browsers don't support custom headers for WebSocket
// Use public endpoints or pass token via query param (less secure)
const ws = new WebSocket('ws://localhost:8080/ws/public');
ws.onopen = () => console.log('Connected');
ws.onmessage = (e) => console.log('Received:', e.data);
ws.send('Hello');
```

### Command Line (websocat)

```bash
# Get JWT token
TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.token')

# Connect with auth headers
websocat "ws://localhost:8080/ws" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Origin: http://localhost:8080"
```

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| `WebSocketSecurityConfigurer` | `WebSocketSecurityConfig` |
| `AbstractSecurityWebSocketMessageBrokerConfigurer` | Security middleware + `OriginValidator` |
| `@PreAuthorize` on message handlers | Manual checks in actor/handler |
| CORS/Origin checking | `OriginValidator` |
| `SimpMessagingTemplate` | Native `actix-ws` session |

## Security Best Practices

1. **Always use TLS** - Use `wss://` in production
2. **Validate Origin** - Prevent CSWSH attacks
3. **Authenticate during handshake** - Before WebSocket upgrade
4. **Set message size limits** - Prevent DoS attacks
5. **Implement timeouts** - Close idle connections
6. **Log connections** - Track who connects and when

## Example Application

Run the complete example:

```bash
cargo run -p actix-security-examples --bin websocket_auth
```

Then visit http://localhost:8080/test for a browser-based test page.
