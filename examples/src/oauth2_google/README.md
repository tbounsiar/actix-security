# Google OAuth2 Authentication Example

This example demonstrates OAuth2 authentication with Google for social login.

## Quick Start

Add these dependencies to your `Cargo.toml`:

```toml
[dependencies]
actix-web = "4"
actix-session = { version = "0.10", features = ["cookie-session"] }
actix-security = { version = "0.2", features = ["oauth2"] }
reqwest = { version = "0.12", features = ["json"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Prerequisites

1. Create a Google Cloud project at https://console.cloud.google.com
2. Enable the Google+ API or Google Identity API
3. Create OAuth2 credentials (Web application type)
4. Add authorized redirect URI: `http://localhost:8080/auth/callback`

## Features

- Google OAuth2 / OpenID Connect
- PKCE (Proof Key for Code Exchange)
- CSRF state protection
- Session-based user storage
- User profile and picture display

## Running the Example

```bash
# Set environment variables
export GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
export GOOGLE_CLIENT_SECRET=your-client-secret

# From the project root
cargo run --bin oauth2_google

# Or from the examples directory
cargo run -p actix-security-examples --bin oauth2_google
```

The server will start at `http://localhost:8080`.

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Home page / user profile |
| `/auth/login` | GET | Start OAuth2 login flow |
| `/auth/callback` | GET | OAuth2 callback |
| `/logout` | GET | Clear session |

## OAuth2 Flow

1. User clicks "Sign in with Google"
2. Server generates authorization URL with state
3. User authenticates at Google
4. Google redirects back with authorization code
5. Server exchanges code for tokens
6. Server fetches user info with access token
7. User profile stored in session

## Testing

1. Open http://localhost:8080 in your browser
2. Click "Sign in with Google"
3. Authenticate with your Google account
4. View your profile on the home page
5. Click "Logout" to sign out

## Scopes Requested

| Scope | Description |
|-------|-------------|
| `openid` | OpenID Connect |
| `email` | User's email address |
| `profile` | User's name and picture |

## Code Overview

```rust
// Configure OAuth2 using actix-security
let oauth2_config = OAuth2Config::new(
    &config.client_id,
    &config.client_secret,
    &config.redirect_uri,
)
.provider(OAuth2Provider::Google)
.scopes(vec!["openid", "email", "profile"]);

// Build authorization URL
let auth_url = format!(
    "https://accounts.google.com/o/oauth2/v2/auth?\
    client_id={}&redirect_uri={}&response_type=code&\
    scope=openid%20email%20profile&state={}",
    client_id, redirect_uri, state
);

// Exchange code for tokens
let tokens = client
    .post("https://oauth2.googleapis.com/token")
    .form(&[("client_id", id), ("code", code), ...])
    .send().await?;
```

## Security Best Practices

1. **Always validate state** - Prevents CSRF attacks
2. **Use HTTPS in production** - Protects tokens in transit
3. **Store secrets securely** - Use environment variables
4. **Validate redirect URIs** - Prevent open redirects
5. **Use PKCE** - Prevents authorization code interception

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| `OAuth2LoginConfigurer` | `OAuth2Config` |
| `CommonOAuth2Provider.GOOGLE` | `OAuth2Provider::Google` |
| `OAuth2AuthorizedClientService` | Session-based storage |
| `@EnableOAuth2Client` | Feature flag `oauth2` |

## Related Examples

- [OIDC Keycloak](../oidc_keycloak/README.md) - Enterprise SSO
- [Form Login](../form_login/README.md) - Form-based auth
- [Session Authentication](../session_auth/README.md) - Session management
