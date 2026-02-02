# JWT Authentication

JSON Web Token (JWT) authentication for stateless API security.

## Overview

JWT authentication is ideal for:
- REST APIs
- Microservices
- Single Page Applications (SPAs)
- Mobile applications

## Feature Flag

Enable JWT support in your `Cargo.toml`:

```toml
[dependencies]
actix-security = { version = "0.2", features = ["jwt"] }
```

## Quick Start

```rust
use actix_security::http::security::jwt::{JwtAuthenticator, JwtConfig};
use actix_security::http::security::middleware::SecurityTransform;

// Configure JWT
let config = JwtConfig::new("your-256-bit-secret-key-minimum!")
    .issuer("my-app")
    .audience("my-api")
    .expiration_hours(24);

let authenticator = JwtAuthenticator::new(config);

// Use with SecurityTransform
App::new()
    .wrap(
        SecurityTransform::new()
            .config_authenticator(move || authenticator.clone())
            .config_authorizer(|| AuthorizationManager::request_matcher())
    )
```

## Configuration Options

```rust
let config = JwtConfig::new("your-secret-key")
    // Algorithm (default: HS256)
    .algorithm(Algorithm::HS512)

    // Issuer claim validation
    .issuer("my-app")

    // Audience claim validation
    .audience("my-api")

    // Token expiration
    .expiration_secs(3600)      // or
    .expiration_hours(1)        // or
    .expiration_days(7)

    // Validation leeway (for clock skew)
    .leeway_secs(60)

    // Custom header (default: "Authorization")
    .header_name("X-Auth-Token")

    // Custom prefix (default: "Bearer ")
    .header_prefix("Token ");
```

## Token Generation

### Generate Token for User

```rust
use actix_security::http::security::jwt::{JwtAuthenticator, JwtConfig};
use actix_security::http::security::User;

let config = JwtConfig::new("secret").expiration_hours(24);
let authenticator = JwtAuthenticator::new(config);

// Create user
let user = User::new("john".to_string(), "".to_string())
    .roles(&["USER".into()])
    .authorities(&["posts:read".into()]);

// Generate token
let token = authenticator.generate_token(&user)?;
// Returns: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Generate Token with Custom Claims

```rust
use actix_security::http::security::jwt::Claims;

let claims = Claims::new("john", 3600)
    .issuer("my-app")
    .audience("my-api")
    .roles(vec!["USER".to_string()])
    .authorities(vec!["posts:read".to_string()])
    .custom(serde_json::json!({
        "tenant_id": "acme",
        "department": "engineering"
    }));

let token = authenticator.generate_token_with_claims(&claims)?;
```

## Token Validation

```rust
// Validate and get claims
let token_data = authenticator.validate_token(&token)?;
let claims = token_data.claims;

println!("Username: {}", claims.sub);
println!("Roles: {:?}", claims.roles);
println!("Expires: {}", claims.exp);
```

## Token Service (Access + Refresh Tokens)

```rust
use actix_security::http::security::jwt::JwtTokenService;

let service = JwtTokenService::new(config)
    .refresh_expiration_days(7);

// Generate access token (short-lived, includes roles)
let access_token = service.generate_token(&user)?;

// Generate refresh token (long-lived, minimal claims)
let refresh_token = service.generate_refresh_token(&user)?;
```

## Complete Example

### Login Endpoint

```rust
use actix_web::{post, web, HttpResponse, Responder};
use actix_security::http::security::jwt::{JwtAuthenticator, JwtConfig};
use actix_security::http::security::{
    AuthenticationManager, Argon2PasswordEncoder, PasswordEncoder, User
};

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

#[post("/auth/login")]
async fn login(
    form: web::Json<LoginRequest>,
    authenticator: web::Data<JwtAuthenticator>,
    users: web::Data<MemoryAuthenticator>,
) -> impl Responder {
    // Validate credentials
    let user = match users.find_user(&form.username) {
        Some(u) if encoder.matches(&form.password, u.get_password()) => u,
        _ => return HttpResponse::Unauthorized().body("Invalid credentials"),
    };

    // Generate token
    match authenticator.generate_token(&user) {
        Ok(token) => HttpResponse::Ok().json(LoginResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: 3600,
        }),
        Err(_) => HttpResponse::InternalServerError().body("Token generation failed"),
    }
}
```

### Protected Endpoint

```rust
use actix_security::secured;
use actix_security::http::security::AuthenticatedUser;

#[secured("USER")]
#[get("/api/profile")]
async fn profile(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "username": user.get_username(),
        "roles": user.get_roles(),
    }))
}
```

### Client Usage

```bash
# Login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "john", "password": "secret"}'

# Response: {"access_token": "eyJ...", "token_type": "Bearer", "expires_in": 3600}

# Access protected resource
curl http://localhost:8080/api/profile \
  -H "Authorization: Bearer eyJ..."
```

## JWT Claims Structure

```json
{
  "sub": "username",
  "iss": "my-app",
  "aud": "my-api",
  "exp": 1735689600,
  "iat": 1735686000,
  "roles": ["USER", "ADMIN"],
  "authorities": ["posts:read", "posts:write"]
}
```

## Algorithms

Supported algorithms:

| Algorithm | Description |
|-----------|-------------|
| `HS256` | HMAC-SHA256 (default) |
| `HS384` | HMAC-SHA384 |
| `HS512` | HMAC-SHA512 |
| `RS256` | RSA-SHA256 |
| `RS384` | RSA-SHA384 |
| `RS512` | RSA-SHA512 |
| `ES256` | ECDSA-SHA256 |
| `ES384` | ECDSA-SHA384 |

## Security Best Practices

1. **Use strong secrets** - At least 256 bits (32 characters) for HMAC
2. **Set appropriate expiration** - Short-lived tokens (15 min - 1 hour)
3. **Use HTTPS** - Always transmit tokens over HTTPS
4. **Validate claims** - Always validate issuer and audience
5. **Store tokens securely** - Never store in localStorage for web apps
6. **Implement token refresh** - Use refresh tokens for long sessions

## Spring Security Comparison

**Spring Security:**
```java
@Bean
public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withSecretKey(secretKey).build();
}

@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
    return http.build();
}
```

**Actix Security:**
```rust
let config = JwtConfig::new("secret-key")
    .issuer("my-app")
    .expiration_hours(1);

let authenticator = JwtAuthenticator::new(config);

SecurityTransform::new()
    .config_authenticator(move || authenticator.clone())
```
