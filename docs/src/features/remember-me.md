# Remember-Me Authentication

Remember-me authentication allows users to stay logged in across browser sessions using a persistent token stored in a cookie.

## Enabling Remember-Me

Add the `remember-me` feature to your `Cargo.toml`:

```toml
[dependencies]
actix-security = { version = "0.2", features = ["remember-me"] }
```

Note: The `remember-me` feature automatically enables the `session` feature.

## Basic Usage

```rust
use actix_security::http::security::{RememberMeServices, RememberMeConfig};
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::{App, HttpServer, cookie::Key};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let secret_key = Key::generate();

    let remember_me = RememberMeServices::new(
        RememberMeConfig::new()
            .key("my-secret-key")
            .validity_seconds(60 * 60 * 24 * 14)  // 14 days
            .cookie_name("remember-me")
    );

    HttpServer::new(move || {
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                secret_key.clone(),
            ))
            // Configure with SecurityTransform
            // ...
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Configuration Options

```rust
RememberMeConfig::new()
    // Secret key for token generation
    .key("your-secret-key-here")

    // Token validity period (default: 14 days)
    .validity_seconds(60 * 60 * 24 * 14)

    // Cookie name (default: "remember-me")
    .cookie_name("remember-me")

    // Cookie path (default: "/")
    .cookie_path("/")

    // Secure cookie (HTTPS only)
    .secure(true)

    // HttpOnly cookie (not accessible via JavaScript)
    .http_only(true)

    // SameSite policy
    .same_site(SameSite::Lax)
```

## Login with Remember-Me

When processing login, check if the user wants to be remembered:

```rust
use actix_security::http::security::RememberMeServices;
use actix_web::{web, HttpResponse, HttpRequest};

async fn login(
    form: web::Form<LoginForm>,
    remember_me: web::Data<RememberMeServices>,
    req: HttpRequest,
) -> HttpResponse {
    // Authenticate user
    if let Some(user) = authenticate(&form.username, &form.password) {
        // Create session
        create_session(&user);

        // If remember-me checkbox was checked
        if form.remember_me {
            // Generate and set remember-me cookie
            let cookie = remember_me.create_token(&user);

            HttpResponse::Found()
                .cookie(cookie)
                .insert_header(("Location", "/dashboard"))
                .finish()
        } else {
            HttpResponse::Found()
                .insert_header(("Location", "/dashboard"))
                .finish()
        }
    } else {
        HttpResponse::Unauthorized().body("Invalid credentials")
    }
}

#[derive(serde::Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    #[serde(default)]
    remember_me: bool,
}
```

## Auto-Login from Remember-Me Token

Check for remember-me token on requests:

```rust
use actix_security::http::security::RememberMeServices;

async fn check_remember_me(
    remember_me: web::Data<RememberMeServices>,
    session: Session,
    req: HttpRequest,
) -> Option<User> {
    // Check if already logged in
    if let Some(user) = session.get::<User>("user").ok().flatten() {
        return Some(user);
    }

    // Try to authenticate from remember-me cookie
    if let Some(user) = remember_me.auto_login(&req) {
        // Create new session
        session.insert("user", &user).ok();
        return Some(user);
    }

    None
}
```

## Logout with Remember-Me

Clear the remember-me cookie on logout:

```rust
async fn logout(
    remember_me: web::Data<RememberMeServices>,
    session: Session,
) -> HttpResponse {
    // Clear session
    session.purge();

    // Clear remember-me cookie
    let removal_cookie = remember_me.logout_cookie();

    HttpResponse::Found()
        .cookie(removal_cookie)
        .insert_header(("Location", "/login"))
        .finish()
}
```

## Token Format

The remember-me token contains:

```
base64(username:expiration:signature)
```

Where:
- `username`: The user's identifier
- `expiration`: Unix timestamp when token expires
- `signature`: HMAC-SHA256 of username + expiration + secret key

## HTML Form Example

```html
<form method="POST" action="/login">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">

    <label>
        <input type="checkbox" name="remember_me" value="true">
        Remember me for 14 days
    </label>

    <button type="submit">Login</button>
</form>
```

## Token Repository

For persistent token storage (more secure):

```rust
use actix_security::http::security::{
    PersistentRememberMeServices,
    PersistentTokenRepository,
};

// Implement your own token repository
struct DatabaseTokenRepository { /* ... */ }

impl PersistentTokenRepository for DatabaseTokenRepository {
    fn create_token(&self, username: &str) -> RememberMeToken;
    fn get_token(&self, series: &str) -> Option<RememberMeToken>;
    fn update_token(&self, series: &str, token_value: &str, last_used: DateTime);
    fn remove_user_tokens(&self, username: &str);
}

let remember_me = PersistentRememberMeServices::new(
    DatabaseTokenRepository::new(db_pool),
    "secret-key",
);
```

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| `RememberMeServices` | `RememberMeServices` |
| `RememberMeConfigurer` | `RememberMeConfig` |
| `TokenBasedRememberMeServices` | `RememberMeServices` (default) |
| `PersistentTokenBasedRememberMeServices` | `PersistentRememberMeServices` |
| `PersistentTokenRepository` | `PersistentTokenRepository` trait |
| `.rememberMe().key()` | `.key()` |
| `.tokenValiditySeconds()` | `.validity_seconds()` |

## Security Considerations

1. **Strong Secret Key**: Use a cryptographically random key, at least 32 bytes
2. **Secure Cookies**: Enable `secure(true)` in production (HTTPS only)
3. **HttpOnly**: Always use `http_only(true)` to prevent XSS attacks
4. **Token Rotation**: Consider using persistent tokens with rotation for better security
5. **Limited Scope**: Remember-me should not grant access to sensitive operations
6. **Session Binding**: Optionally bind remember-me tokens to additional factors (IP, user-agent)

## Best Practices

- Don't use remember-me for sensitive operations (payments, password changes)
- Provide users a way to invalidate all remember-me tokens (logout everywhere)
- Monitor for suspicious remember-me usage patterns
- Consider shorter validity periods for higher security requirements
