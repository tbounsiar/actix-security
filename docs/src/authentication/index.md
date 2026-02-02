# Authentication

Authentication is the process of verifying **who** a user is. Actix Security provides a flexible authentication system inspired by Spring Security.

## Core Concepts

### The Authenticator Trait

All authentication is handled through the `Authenticator` trait:

```rust
pub trait Authenticator: Clone + Send + Sync + 'static {
    /// Authenticate a request and return the user if successful.
    fn get_user(&self, req: &ServiceRequest) -> Option<User>;
}
```

Implement this trait to create custom authentication mechanisms.

### The User Model

A `User` represents an authenticated identity:

```rust
pub struct User {
    pub username: String,
    pub password: String,  // Encoded password
    pub roles: HashSet<String>,
    pub authorities: HashSet<String>,
}
```

### AuthenticatedUser Extractor

In your handlers, use `AuthenticatedUser` to access the current user:

```rust
use actix_security::http::security::AuthenticatedUser;

#[get("/profile")]
async fn profile(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Hello, {}!", user.get_username()))
}
```

## Built-in Authenticators

### MemoryAuthenticator

An in-memory user store, perfect for development and testing:

```rust
use actix_security::http::security::{
    AuthenticationManager, Argon2PasswordEncoder, PasswordEncoder, User
};

let encoder = Argon2PasswordEncoder::new();

let authenticator = AuthenticationManager::in_memory_authentication()
    .password_encoder(encoder.clone())
    .with_user(
        User::with_encoded_password("admin", encoder.encode("secret"))
            .roles(&["ADMIN".into()])
    )
    .with_user(
        User::with_encoded_password("user", encoder.encode("password"))
            .roles(&["USER".into()])
    );
```

### JwtAuthenticator

Stateless JWT-based authentication for REST APIs (requires `jwt` feature):

```rust
use actix_security::http::security::jwt::{JwtAuthenticator, JwtConfig};

let config = JwtConfig::new("your-256-bit-secret-key-minimum!")
    .issuer("my-app")
    .audience("my-api")
    .expiration_hours(24);

let authenticator = JwtAuthenticator::new(config);
```

### SessionAuthenticator

Server-side session-based authentication (requires `session` feature):

```rust
use actix_security::http::security::session::{SessionAuthenticator, SessionConfig};

let config = SessionConfig::new()
    .user_key("authenticated_user")
    .authenticated_key("is_authenticated");

let authenticator = SessionAuthenticator::new(config);
```

### OAuth2Client

OAuth2/OIDC authentication for social login (requires `oauth2` feature):

```rust
use actix_security::http::security::oauth2::{OAuth2Config, OAuth2Provider, OAuth2Client};

let config = OAuth2Config::new("client-id", "client-secret", "redirect-uri")
    .provider(OAuth2Provider::Google);

let client = OAuth2Client::new(config).await?;

// Generate authorization URL
let (auth_url, state, pkce_verifier, nonce) = client.authorization_url();
```

## Authentication Flow

```
Request → SecurityTransform → Authenticator.authenticate()
                                    ↓
                            ┌───────────────┐
                            │ User found?   │
                            └───────┬───────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ↓                               ↓
              [Yes: User]                    [No: None]
                    ↓                               ↓
           Continue to Authorizer           401 Unauthorized
                                          or redirect to login
```

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| `AuthenticationManager` | `Authenticator` trait |
| `UserDetailsService` | `Authenticator::get_user()` |
| `UserDetails` | `User` |
| `Authentication` | `AuthenticatedUser` |
| `InMemoryUserDetailsManager` | `MemoryAuthenticator` |
| `JwtDecoder` | `JwtAuthenticator` |
| `SessionRegistry` | `SessionAuthenticator` |
| `ClientRegistrationRepository` | `OAuth2ClientRepository` |
| `OAuth2User` | `OAuth2User` |
| `PasswordEncoder` | `PasswordEncoder` trait |

## Sections

- [In-Memory Authentication](./memory.md) - Quick setup with `MemoryAuthenticator`
- [Password Encoding](./password-encoding.md) - Secure password storage
- [HTTP Basic](./http-basic.md) - HTTP Basic authentication
- [JWT Authentication](./jwt.md) - Stateless token-based authentication for APIs
- [Session Authentication](./session-auth.md) - Server-side session management
- [OAuth2 / OIDC](./oauth2.md) - Social login and enterprise SSO
- [Custom Authenticators](./custom.md) - Build your own
