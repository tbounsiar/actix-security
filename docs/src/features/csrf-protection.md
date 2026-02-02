# CSRF Protection

Cross-Site Request Forgery (CSRF) protection prevents attackers from tricking users into performing unwanted actions.

## Enabling CSRF Protection

Add the `csrf` feature to your `Cargo.toml`:

```toml
[dependencies]
actix-security = { version = "0.2", features = ["csrf"] }
```

## Basic Usage

```rust
use actix_security::http::security::{CsrfProtection, CsrfConfig};
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::{App, HttpServer, cookie::Key};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let secret_key = Key::generate();

    let csrf = CsrfProtection::new(CsrfConfig::default());

    HttpServer::new(move || {
        App::new()
            // Session middleware is required for CSRF
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                secret_key.clone(),
            ))
            .wrap(csrf.clone())
            // ... routes
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Configuration Options

```rust
CsrfConfig::new()
    // Name of the form field containing the token
    .token_parameter("_csrf")

    // Name of the HTTP header containing the token
    .header_name("X-CSRF-TOKEN")

    // Session key for storing the token
    .session_key("csrf_token")

    // Paths to exclude from CSRF checks
    .ignore_path("/api/webhook")
    .ignore_paths(vec!["/api/public/*"])

    // Methods that don't require CSRF (safe methods)
    // Default: GET, HEAD, OPTIONS, TRACE
    .ignore_method(Method::GET)
```

## Token in Forms

Include the CSRF token in your HTML forms:

```html
<form method="POST" action="/submit">
    <input type="hidden" name="_csrf" value="{{ csrf_token }}">
    <!-- other form fields -->
    <button type="submit">Submit</button>
</form>
```

To get the CSRF token in your handler:

```rust
use actix_security::http::security::CsrfToken;
use actix_session::Session;

async fn show_form(session: Session) -> impl Responder {
    // Generate or retrieve CSRF token
    let token = CsrfToken::generate();
    session.insert("csrf_token", &token.token).ok();

    let html = format!(r#"
        <form method="POST" action="/submit">
            <input type="hidden" name="_csrf" value="{}">
            <button type="submit">Submit</button>
        </form>
    "#, token.token);

    HttpResponse::Ok().content_type("text/html").body(html)
}
```

## Token in AJAX Requests

For JavaScript/AJAX requests, include the token in a header:

```javascript
// Get token from meta tag or cookie
const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

fetch('/api/action', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-TOKEN': csrfToken
    },
    body: JSON.stringify(data)
});
```

## Token Repository

By default, tokens are stored in the session. You can customize this:

```rust
use actix_security::http::security::{CsrfTokenRepository, SessionCsrfTokenRepository};

// Session-based (default)
CsrfConfig::new()
    .token_repository(SessionCsrfTokenRepository::new())
```

## Error Handling

When CSRF validation fails, a 403 Forbidden response is returned by default.

```rust
use actix_security::http::security::CsrfError;

// CsrfError variants:
CsrfError::MissingToken    // No token in request
CsrfError::InvalidToken    // Token doesn't match
CsrfError::SessionError    // Session storage issue
```

## When to Use CSRF Protection

- **Enable for**: Form submissions, state-changing operations
- **Disable for**: APIs using token-based auth (JWT), webhooks, public endpoints

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| `CsrfFilter` | `CsrfProtection` middleware |
| `CsrfToken` | `CsrfToken` |
| `CsrfTokenRepository` | `CsrfTokenRepository` trait |
| `HttpSessionCsrfTokenRepository` | `SessionCsrfTokenRepository` |
| `.csrf().disable()` | `.ignore_path()` |
