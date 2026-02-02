# OpenID Connect with Keycloak Example

This example demonstrates OAuth2/OpenID Connect authentication with Keycloak using the actix-security library.

## Quick Start

Add these dependencies to your `Cargo.toml`:

```toml
[dependencies]
actix-web = "4"
actix-security = { version = "0.2", features = ["oauth2", "session"] }
actix-session = { version = "0.10", features = ["cookie-session"] }
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Features

- OpenID Connect authentication flow
- Keycloak integration
- JWT token validation
- User info endpoint access
- Role mapping from Keycloak
- Token refresh

## Prerequisites

### Keycloak Setup

1. **Run Keycloak** (Docker):
   ```bash
   docker run -p 8180:8080 \
     -e KEYCLOAK_ADMIN=admin \
     -e KEYCLOAK_ADMIN_PASSWORD=admin \
     quay.io/keycloak/keycloak:latest start-dev
   ```

2. **Access Admin Console**: `http://localhost:8180/admin`
   - Username: `admin`
   - Password: `admin`

3. **Create a Realm**:
   - Click "Create Realm"
   - Name: `actix-security`
   - Click "Create"

4. **Create a Client**:
   - Go to Clients → Create Client
   - Client ID: `actix-example`
   - Client Protocol: `openid-connect`
   - Click "Next"
   - Enable "Client authentication"
   - Enable "Standard flow" and "Direct access grants"
   - Click "Save"

5. **Configure Client**:
   - Valid Redirect URIs: `http://localhost:8080/auth/callback`
   - Web Origins: `http://localhost:8080`

6. **Get Client Secret**:
   - Go to Credentials tab
   - Copy "Client secret"

7. **Create Test Users**:
   - Go to Users → Add user
   - Username: `testuser`
   - Enable "Email verified"
   - Go to Credentials → Set password: `test123`
   - Disable "Temporary"

8. **Create Roles** (optional):
   - Go to Realm roles → Create role
   - Create `admin` and `user` roles
   - Assign roles to users in Users → Role mappings

## Running the Example

```bash
# Set environment variables
export KEYCLOAK_URL=http://localhost:8180
export KEYCLOAK_REALM=actix-security
export KEYCLOAK_CLIENT_ID=actix-example
export KEYCLOAK_CLIENT_SECRET=your-client-secret

# Run the example
cargo run --bin oidc_keycloak
```

The server will start at `http://localhost:8080`.

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | Home page with login link |
| `/login` | Initiate OIDC login |
| `/auth/callback` | OIDC callback handler |
| `/logout` | Logout and redirect to Keycloak |
| `/protected` | Protected resource |
| `/userinfo` | Display user information |

## Testing

### Browser Flow

1. Navigate to `http://localhost:8080`
2. Click "Login with Keycloak"
3. Authenticate on Keycloak login page
4. You'll be redirected back with an authenticated session
5. Access `/userinfo` to see user details
6. Click "Logout" to end session

### Programmatic Access (Direct Grants)

```bash
# Get token from Keycloak
TOKEN=$(curl -X POST "http://localhost:8180/realms/actix-security/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=actix-example" \
  -d "client_secret=your-secret" \
  -d "username=testuser" \
  -d "password=test123" | jq -r '.access_token')

# Access protected resource
curl http://localhost:8080/protected \
  -H "Authorization: Bearer $TOKEN"
```

## Code Overview

```rust
// OAuth2/OIDC configuration
let oauth2_config = OAuth2Config::keycloak(
    "http://localhost:8180",
    "actix-security",
    "actix-example",
    "your-client-secret",
)
.redirect_uri("http://localhost:8080/auth/callback")
.scopes(vec!["openid", "profile", "email"]);

// Create OAuth2 client
let oauth2_client = OAuth2Client::new(oauth2_config)?;

// Initiate login
let (auth_url, csrf_state) = oauth2_client.authorization_url();

// Handle callback
let token = oauth2_client.exchange_code(code, state).await?;

// Get user info
let user_info = oauth2_client.userinfo(&token.access_token).await?;
```

## Keycloak Role Mapping

Roles from Keycloak are automatically mapped to actix-security roles:

```rust
// In Keycloak token claims
{
  "realm_access": {
    "roles": ["admin", "user"]
  }
}

// Mapped to User
user.has_role("ADMIN") // true
user.has_role("USER")  // true
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
                .requestMatchers("/protected/**").authenticated()
                .anyRequest().permitAll())
            .oauth2Login()
            .and()
            .oauth2ResourceServer(oauth2 -> oauth2.jwt());
        return http.build();
    }
}

// application.yml
spring:
  security:
    oauth2:
      client:
        registration:
          keycloak:
            client-id: actix-example
            client-secret: your-secret
            scope: openid,profile,email
        provider:
          keycloak:
            issuer-uri: http://localhost:8180/realms/actix-security
```

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `client_id` | OAuth2 client ID | Required |
| `client_secret` | OAuth2 client secret | Required |
| `redirect_uri` | Callback URL | Required |
| `scopes` | OAuth2 scopes | ["openid"] |
| `issuer_url` | OIDC issuer URL | Required |

## Troubleshooting

### Invalid redirect URI
- Ensure the callback URL matches exactly in Keycloak client settings

### Token validation fails
- Check that the Keycloak URL is accessible
- Verify the realm name is correct
- Ensure clock sync between servers

### Missing roles
- Check Keycloak role mappings
- Verify "Full scope allowed" in client settings

## Related Examples

- [JWT Auth](../jwt_auth/README.md) - Standalone JWT authentication
- [Session Auth](../session_auth/README.md) - Session management
- [Security Complete](../security_complete/README.md) - All features combined
