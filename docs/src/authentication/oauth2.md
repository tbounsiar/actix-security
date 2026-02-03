# OAuth2 / OpenID Connect Authentication

OAuth2 and OpenID Connect (OIDC) authentication for social login and enterprise SSO.

## Overview

OAuth2/OIDC authentication is ideal for:
- Social login (Google, GitHub, Facebook, etc.)
- Enterprise SSO (Okta, Auth0, Keycloak, Azure AD)
- Single Sign-On across multiple applications
- Delegated authentication

## Feature Flag

Enable OAuth2 support in your `Cargo.toml`:

```toml
[dependencies]
actix-security = { version = "0.2", features = ["oauth2"] }
```

## Quick Start

### Google OAuth2

```rust
use actix_security::http::security::oauth2::{
    OAuth2Config, OAuth2Provider, OAuth2Client
};

// Configure Google OAuth2
let config = OAuth2Config::new(
    std::env::var("GOOGLE_CLIENT_ID").unwrap(),
    std::env::var("GOOGLE_CLIENT_SECRET").unwrap(),
    "http://localhost:8080/oauth2/callback/google"
)
.provider(OAuth2Provider::Google);

// Create client (async - performs OIDC discovery)
let client = OAuth2Client::new(config).await?;

// Generate authorization URL
let (auth_url, state, pkce_verifier, nonce) = client.authorization_url();

// Redirect user to auth_url...
// Store state, pkce_verifier, and nonce in session for callback verification
```

### GitHub OAuth2

```rust
let config = OAuth2Config::new(
    std::env::var("GITHUB_CLIENT_ID").unwrap(),
    std::env::var("GITHUB_CLIENT_SECRET").unwrap(),
    "http://localhost:8080/oauth2/callback/github"
)
.provider(OAuth2Provider::GitHub);

// GitHub doesn't support OIDC, so no discovery needed
let client = OAuth2Client::new_basic(config)?;
```

## Supported Providers

| Provider | OIDC Support | PKCE Support | Default Scopes |
|----------|--------------|--------------|----------------|
| Google | Yes | Yes | `openid`, `email`, `profile` |
| GitHub | No | No | `read:user`, `user:email` |
| Microsoft | Yes | Yes | `openid`, `email`, `profile` |
| Facebook | No | No | `email`, `public_profile` |
| Apple | Yes | Yes | `openid`, `email`, `name` |
| Okta | Yes | Yes | `openid`, `email`, `profile` |
| Auth0 | Yes | Yes | `openid`, `email`, `profile` |
| Keycloak | Yes | Yes | `openid`, `email`, `profile` |

### Automatic PKCE Handling

PKCE (Proof Key for Code Exchange) is automatically configured based on the provider:

```rust
// Google: PKCE is enabled by default (use_pkce = true)
let google = OAuth2Config::new(id, secret, redirect)
    .provider(OAuth2Provider::Google);
assert!(google.use_pkce);  // true

// GitHub: PKCE is automatically disabled (not supported)
let github = OAuth2Config::new(id, secret, redirect)
    .provider(OAuth2Provider::GitHub);
assert!(!github.use_pkce);  // false
```

### Registration ID

The `registration_id` identifies the provider in URLs and callbacks:

```rust
// Automatically set from provider name
let config = OAuth2Config::new(id, secret, redirect)
    .provider(OAuth2Provider::Google);
assert_eq!(config.registration_id, "google");

// Or set explicitly for custom naming
let config = OAuth2Config::new(id, secret, redirect)
    .registration_id("my-google-oauth")
    .provider(OAuth2Provider::Google);
assert_eq!(config.registration_id, "my-google-oauth");
```

## Configuration Options

```rust
let config = OAuth2Config::new("client-id", "client-secret", "redirect-uri")
    // Use a pre-configured provider
    .provider(OAuth2Provider::Google)

    // Or configure custom endpoints
    .authorization_uri("https://auth.example.com/authorize")
    .token_uri("https://auth.example.com/token")
    .userinfo_uri("https://auth.example.com/userinfo")

    // OIDC issuer for auto-discovery
    .issuer_uri("https://auth.example.com")

    // Scopes
    .scopes(vec!["openid", "email", "profile"])
    .add_scope("custom_scope")

    // PKCE (enabled by default for supported providers)
    .use_pkce(true)

    // Username attribute extraction
    .username_attribute("email")  // Use email as username

    // Custom authorization parameters
    .authorization_param("prompt", "consent");
```

## Authorization Code Flow

### Step 1: Generate Authorization URL

```rust
use actix_web::{get, web, HttpResponse};
use actix_session::Session;

#[get("/oauth2/authorize/{provider}")]
async fn authorize(
    provider: web::Path<String>,
    session: Session,
    clients: web::Data<OAuth2ClientRepository>,
) -> HttpResponse {
    let client = clients.get_client(&provider).unwrap();

    // Generate authorization URL with PKCE and nonce
    let (auth_url, state, pkce_verifier, nonce) = client.authorization_url();

    // Store state in session for CSRF protection
    session.insert("oauth2_state", state.secret()).unwrap();

    // Store PKCE verifier for token exchange
    if let Some(verifier) = pkce_verifier {
        session.insert("oauth2_pkce", verifier.secret()).unwrap();
    }

    // Store nonce for OIDC token validation
    if let Some(n) = nonce {
        session.insert("oauth2_nonce", n.secret()).unwrap();
    }

    HttpResponse::Found()
        .append_header(("Location", auth_url.to_string()))
        .finish()
}
```

### Step 2: Handle Callback

```rust
use oauth2::{CsrfToken, PkceCodeVerifier};
use openidconnect::Nonce;

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

#[get("/oauth2/callback/{provider}")]
async fn callback(
    provider: web::Path<String>,
    query: web::Query<CallbackQuery>,
    session: Session,
    clients: web::Data<OAuth2ClientRepository>,
) -> HttpResponse {
    let client = clients.get_client(&provider).unwrap();

    // Verify state (CSRF protection)
    let stored_state: String = session.get("oauth2_state").unwrap().unwrap();
    if query.state != stored_state {
        return HttpResponse::BadRequest().body("Invalid state");
    }

    // Retrieve PKCE verifier
    let pkce_verifier = session
        .get::<String>("oauth2_pkce")
        .unwrap()
        .map(|s| PkceCodeVerifier::new(s));

    // Retrieve nonce for OIDC
    let nonce = session
        .get::<String>("oauth2_nonce")
        .unwrap()
        .map(|s| Nonce::new(s));

    // Exchange code for tokens
    let (oauth2_user, oidc_user) = client
        .exchange_code(&query.code, pkce_verifier, nonce.as_ref())
        .await
        .map_err(|e| HttpResponse::InternalServerError().body(e.to_string()))?;

    // Convert to authenticated user
    let user = oauth2_user.to_user();

    // Store user in session
    session.insert("user", serde_json::to_string(&oauth2_user).unwrap()).unwrap();

    HttpResponse::Found()
        .append_header(("Location", "/"))
        .finish()
}
```

## OAuth2User

The `OAuth2User` contains information retrieved from the OAuth2 provider:

```rust
pub struct OAuth2User {
    pub sub: String,              // Unique identifier
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub picture: Option<String>,
    pub locale: Option<String>,
    pub attributes: HashMap<String, Value>,  // Provider-specific
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: Option<i64>,
    pub provider: String,
}

// Get username (prefers email, falls back to sub)
let username = oauth2_user.username();

// Convert to security User
let user = oauth2_user.to_user();
// User has role "USER" and authority "OAUTH2_USER_GOOGLE"
```

## OidcUser

For OIDC providers, you also get ID token claims:

```rust
pub struct OidcUser {
    pub oauth2_user: OAuth2User,
    pub id_token_claims: Option<IdTokenClaims>,
    pub id_token: Option<String>,  // Raw JWT
}

pub struct IdTokenClaims {
    pub iss: String,    // Issuer
    pub sub: String,    // Subject
    pub aud: Vec<String>,  // Audience
    pub exp: i64,       // Expiration
    pub iat: i64,       // Issued at
    pub auth_time: Option<i64>,
    pub nonce: Option<String>,
    pub at_hash: Option<String>,
}
```

## Multiple Providers

Use `OAuth2ClientRepository` to manage multiple providers:

```rust
use actix_security::http::security::oauth2::OAuth2ClientRepository;

// Build repository from configs
let configs = vec![
    OAuth2Config::new(google_id, google_secret, google_redirect)
        .provider(OAuth2Provider::Google),
    OAuth2Config::new(github_id, github_secret, github_redirect)
        .provider(OAuth2Provider::GitHub),
];

let repository = OAuth2ClientRepository::from_configs(configs).await?;

// Use in Actix Web
App::new()
    .app_data(web::Data::new(repository))
    .service(authorize)
    .service(callback)
```

## Custom Provider

Configure a custom OAuth2/OIDC provider:

```rust
let config = OAuth2Config::new("client-id", "secret", "redirect-uri")
    .registration_id("custom")
    .authorization_uri("https://custom.example.com/oauth/authorize")
    .token_uri("https://custom.example.com/oauth/token")
    .userinfo_uri("https://custom.example.com/oauth/userinfo")
    // For OIDC with discovery:
    .issuer_uri("https://custom.example.com")
    .scopes(vec!["openid", "email", "profile"]);
```

## Complete Example

```rust
use actix_web::{get, web, App, HttpServer, HttpResponse};
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_web::cookie::Key;
use actix_security::http::security::oauth2::{
    OAuth2Config, OAuth2Provider, OAuth2Client, OAuth2ClientRepository
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Configure OAuth2 providers
    let google_config = OAuth2Config::new(
        std::env::var("GOOGLE_CLIENT_ID").unwrap(),
        std::env::var("GOOGLE_CLIENT_SECRET").unwrap(),
        "http://localhost:8080/oauth2/callback/google"
    )
    .provider(OAuth2Provider::Google);

    let repository = OAuth2ClientRepository::from_configs(vec![google_config])
        .await
        .expect("Failed to create OAuth2 repository");

    let secret_key = Key::generate();

    HttpServer::new(move || {
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                secret_key.clone()
            ))
            .app_data(web::Data::new(repository.clone()))
            .service(login_page)
            .service(authorize)
            .service(callback)
            .service(profile)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

#[get("/login")]
async fn login_page() -> HttpResponse {
    HttpResponse::Ok().body(r#"
        <a href="/oauth2/authorize/google">Login with Google</a>
    "#)
}

#[get("/profile")]
async fn profile(session: Session) -> HttpResponse {
    if let Some(user_json) = session.get::<String>("user").unwrap() {
        HttpResponse::Ok().body(format!("Logged in as: {}", user_json))
    } else {
        HttpResponse::Found()
            .append_header(("Location", "/login"))
            .finish()
    }
}
```

## Security Best Practices

1. **Always validate state** - Prevents CSRF attacks
2. **Use PKCE** - Prevents authorization code interception
3. **Validate nonce for OIDC** - Prevents replay attacks
4. **Use HTTPS** - Always in production
5. **Validate redirect URIs** - Prevent open redirects
6. **Store tokens securely** - Use encrypted sessions
7. **Handle token expiration** - Implement refresh token flow

## Spring Security Comparison

**Spring Security:**
```java
@Configuration
public class OAuth2Config {
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(
            CommonOAuth2Provider.GOOGLE.getBuilder("google")
                .clientId("client-id")
                .clientSecret("client-secret")
                .build()
        );
    }
}
```

**Actix Security:**
```rust
let config = OAuth2Config::new("client-id", "client-secret", "redirect-uri")
    .provider(OAuth2Provider::Google);

let repository = OAuth2ClientRepository::from_configs(vec![config]).await?;
```
