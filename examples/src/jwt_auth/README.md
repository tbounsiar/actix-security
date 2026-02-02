# JWT Authentication Example

This example demonstrates JWT (JSON Web Token) authentication using the actix-security library.

## Features

- JWT token generation and validation
- Access token and refresh token support
- Configurable token expiration
- Role and authority extraction from claims
- Bearer token authentication

## Running the Example

```bash
# From the project root
cargo run --bin jwt_auth

# Or from the examples directory
cargo run -p actix-security-examples --bin jwt_auth
```

The server will start at `http://localhost:8080`.

## Endpoints

| Endpoint | Method | Authorization | Description |
|----------|--------|---------------|-------------|
| `/login` | POST | None | Get JWT token |
| `/protected` | GET | Bearer token | Protected resource |
| `/admin` | GET | Role: ADMIN | Admin-only resource |
| `/refresh` | POST | Refresh token | Refresh access token |

## Test Users

| Username | Password | Roles |
|----------|----------|-------|
| admin | admin | ADMIN, USER |
| user | user | USER |

## Testing

### Get a JWT Token

```bash
# Login and get token
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'

# Response
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Use the Token

```bash
# Store the token
TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

# Access protected endpoint
curl http://localhost:8080/protected \
  -H "Authorization: Bearer $TOKEN"

# Access admin endpoint
curl http://localhost:8080/admin \
  -H "Authorization: Bearer $TOKEN"
```

### Without Token (401 Unauthorized)

```bash
curl http://localhost:8080/protected
# Returns 401 Unauthorized
```

## Code Overview

```rust
// JWT configuration
let jwt_config = JwtConfig::new()
    .secret("your-secret-key-min-32-chars-long!")
    .issuer("actix-security-example")
    .audience("example-app")
    .expiration(Duration::from_secs(3600));

// JWT token service
let token_service = JwtTokenService::new(jwt_config.clone());

// Generate token
let token = token_service.generate_token(&user)?;

// Create authenticator
let authenticator = JwtAuthenticator::new(jwt_config);
```

## Token Structure

JWT tokens contain three parts separated by dots:
- **Header**: Algorithm and token type
- **Payload**: Claims (sub, roles, authorities, exp, iat, iss, aud)
- **Signature**: Verification signature

Example decoded payload:
```json
{
  "sub": "admin",
  "roles": ["ADMIN", "USER"],
  "authorities": [],
  "exp": 1699999999,
  "iat": 1699996399,
  "iss": "actix-security-example",
  "aud": "example-app"
}
```

## Spring Security Equivalent

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/protected/**").authenticated()
                .anyRequest().permitAll())
            .oauth2ResourceServer(oauth2 -> oauth2.jwt());
        return http.build();
    }
}
```

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `secret` | HMAC secret key (min 32 chars) | Required |
| `issuer` | Token issuer (iss claim) | None |
| `audience` | Token audience (aud claim) | None |
| `expiration` | Token lifetime | 1 hour |
| `algorithm` | Signing algorithm | HS256 |

## Related Examples

- [Basic Auth](../basic_auth/README.md) - HTTP Basic authentication
- [Session Auth](../session_auth/README.md) - Session-based authentication
- [OIDC Keycloak](../oidc_keycloak/README.md) - OpenID Connect with Keycloak
