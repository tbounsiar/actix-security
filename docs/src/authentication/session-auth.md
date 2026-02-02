# Session Authentication

Traditional session-based authentication using cookies.

## Overview

Session authentication is ideal for:
- Traditional web applications
- Server-rendered pages
- Applications requiring logout/session invalidation

## Feature Flag

Enable session support in your `Cargo.toml`:

```toml
[dependencies]
actix-security = { version = "0.2", features = ["session"] }
actix-session = { version = "0.10", features = ["cookie-session"] }
```

## Quick Start

```rust
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_session::config::CookieContentSecurity;
use actix_web::cookie::Key;
use actix_security::http::security::session::{SessionAuthenticator, SessionConfig};
use actix_security::http::security::middleware::SecurityTransform;

// Generate a secure key (in production, load from environment)
let secret_key = Key::generate();

// Session middleware
let session_middleware = SessionMiddleware::builder(
    CookieSessionStore::default(),
    secret_key.clone()
)
.cookie_secure(true)  // HTTPS only in production
.cookie_content_security(CookieContentSecurity::Private)
.build();

// Session authenticator
let session_config = SessionConfig::new();
let authenticator = SessionAuthenticator::new(session_config.clone());

App::new()
    .wrap(session_middleware)
    .wrap(
        SecurityTransform::new()
            .config_authenticator(move || authenticator.clone())
            .config_authorizer(|| AuthorizationManager::request_matcher())
    )
    .app_data(web::Data::new(session_config))
```

## Configuration

```rust
let config = SessionConfig::new()
    // Custom session key for user data (default: "security_user")
    .user_key("my_user")
    // Custom session key for auth flag (default: "security_authenticated")
    .authenticated_key("my_auth");
```

## Login/Logout

### Login Handler

```rust
use actix_session::Session;
use actix_security::http::security::session::{SessionAuthenticator, SessionConfig};
use actix_security::http::security::User;

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[post("/login")]
async fn login(
    session: Session,
    form: web::Form<LoginForm>,
    config: web::Data<SessionConfig>,
    users: web::Data<MemoryAuthenticator>,
    encoder: web::Data<Argon2PasswordEncoder>,
) -> impl Responder {
    // Find user
    let user = match users.find_user(&form.username) {
        Some(u) => u,
        None => return HttpResponse::Unauthorized().body("Invalid credentials"),
    };

    // Verify password
    if !encoder.matches(&form.password, user.get_password()) {
        return HttpResponse::Unauthorized().body("Invalid credentials");
    }

    // Store user in session
    match SessionAuthenticator::login(&session, &user, &config) {
        Ok(_) => HttpResponse::Ok().body(format!("Welcome, {}!", user.get_username())),
        Err(e) => HttpResponse::InternalServerError().body(format!("Login failed: {}", e)),
    }
}
```

### Logout Handler

```rust
#[post("/logout")]
async fn logout(session: Session, config: web::Data<SessionConfig>) -> impl Responder {
    SessionAuthenticator::logout(&session, &config);
    HttpResponse::Ok().body("Logged out")
}

// Or clear entire session
#[post("/logout/all")]
async fn logout_all(session: Session) -> impl Responder {
    SessionAuthenticator::clear_session(&session);
    HttpResponse::Ok().body("Session cleared")
}
```

## Session Utilities

### Check Authentication

```rust
#[get("/status")]
async fn auth_status(session: Session, config: web::Data<SessionConfig>) -> impl Responder {
    if SessionAuthenticator::is_authenticated(&session, &config) {
        let user = SessionAuthenticator::get_session_user(&session, &config);
        HttpResponse::Ok().json(serde_json::json!({
            "authenticated": true,
            "username": user.map(|u| u.get_username().to_string())
        }))
    } else {
        HttpResponse::Ok().json(serde_json::json!({
            "authenticated": false
        }))
    }
}
```

## Complete Example

```rust
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_web::cookie::Key;
use actix_security::secured;
use actix_security::http::security::{
    AuthenticatedUser, AuthenticationManager, AuthorizationManager,
    Argon2PasswordEncoder, PasswordEncoder, User,
};
use actix_security::http::security::session::{SessionAuthenticator, SessionConfig};
use actix_security::http::security::middleware::SecurityTransform;

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Welcome! Please login at /login")
}

#[get("/login")]
async fn login_page() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html")
        .body(r#"
            <form method="post" action="/login">
                <input name="username" placeholder="Username">
                <input name="password" type="password" placeholder="Password">
                <button type="submit">Login</button>
            </form>
        "#)
}

#[post("/login")]
async fn do_login(
    session: Session,
    form: web::Form<LoginForm>,
    config: web::Data<SessionConfig>,
) -> impl Responder {
    // In real app, validate against database
    if form.username == "admin" && form.password == "admin" {
        let user = User::new("admin".to_string(), "".to_string())
            .roles(&["ADMIN".into(), "USER".into()]);

        SessionAuthenticator::login(&session, &user, &config).unwrap();
        HttpResponse::Found()
            .insert_header(("Location", "/dashboard"))
            .finish()
    } else {
        HttpResponse::Unauthorized().body("Invalid credentials")
    }
}

#[post("/logout")]
async fn logout(session: Session, config: web::Data<SessionConfig>) -> impl Responder {
    SessionAuthenticator::logout(&session, &config);
    HttpResponse::Found()
        .insert_header(("Location", "/"))
        .finish()
}

#[secured("USER")]
#[get("/dashboard")]
async fn dashboard(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Welcome to dashboard, {}!", user.get_username()))
}

#[secured("ADMIN")]
#[get("/admin")]
async fn admin(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Admin panel for {}", user.get_username()))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let secret_key = Key::generate();
    let session_config = SessionConfig::new();

    HttpServer::new(move || {
        let config = session_config.clone();
        let authenticator = SessionAuthenticator::new(config.clone());

        App::new()
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .build()
            )
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(move || authenticator.clone())
                    .config_authorizer(|| {
                        AuthorizationManager::request_matcher()
                            .login_url("/login")
                    })
            )
            .app_data(web::Data::new(config))
            .service(index)
            .service(login_page)
            .service(do_login)
            .service(logout)
            .service(dashboard)
            .service(admin)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Session Storage Options

### Cookie Session (Default)

```rust
use actix_session::storage::CookieSessionStore;

SessionMiddleware::new(CookieSessionStore::default(), secret_key)
```

### Redis Session

```toml
[dependencies]
actix-session = { version = "0.10", features = ["redis-session"] }
```

```rust
use actix_session::storage::RedisSessionStore;

let redis_store = RedisSessionStore::new("redis://127.0.0.1:6379").await?;
SessionMiddleware::new(redis_store, secret_key)
```

## Security Best Practices

1. **Use secure cookies** - Set `cookie_secure(true)` in production
2. **Use HTTP-only cookies** - Prevents JavaScript access
3. **Set appropriate expiration** - Balance security and UX
4. **Regenerate session on login** - Prevent session fixation
5. **Use HTTPS** - Always use HTTPS in production
6. **Implement CSRF protection** - For form submissions

## Spring Security Comparison

**Spring Security:**
```java
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard"))
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/"));
        return http.build();
    }
}
```

**Actix Security:**
```rust
// Session middleware handles cookie management
SessionMiddleware::new(CookieSessionStore::default(), secret_key)

// Login/logout handled in handlers
SessionAuthenticator::login(&session, &user, &config)?;
SessionAuthenticator::logout(&session, &config);
```
