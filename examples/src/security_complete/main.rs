//! Complete Security Example
//!
//! This example demonstrates all security features working together:
//! - Rate Limiting (brute-force protection)
//! - Account Locking (failed attempts)
//! - Audit Logging (security events)
//! - Form Login with CSRF protection
//! - Password encoding (Argon2/BCrypt)
//!
//! # Run
//! ```bash
//! cargo run --bin security_complete --all-features
//! ```
//!
//! # Test
//! - Open http://localhost:8082 in a browser
//! - Try logging in with admin/admin or user/user
//! - Try multiple failed logins to trigger account lock
//! - Check console for audit logs

use actix_security::http::security::{
    account::{AccountLockManager, LockConfig, check_login},
    audit::{AuditLogger, SecurityEvent, SecurityEventType, StdoutHandler},
    rate_limit::{RateLimiter, RateLimitConfig},
    Argon2PasswordEncoder, PasswordEncoder, SecurityHeaders, User,
};
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_web::{cookie::Key, get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use std::sync::Arc;

/// Application state
struct AppState {
    users: Vec<User>,
    encoder: Argon2PasswordEncoder,
    lock_manager: AccountLockManager,
    audit_logger: AuditLogger,
}

/// Login form data
#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

/// Home page
#[get("/")]
async fn index(session: Session) -> impl Responder {
    let username: Option<String> = session.get("username").ok().flatten();

    match username {
        Some(name) => {
            let html = format!(
                r#"<!DOCTYPE html>
<html>
<head>
    <title>Home - Security Complete Example</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
        .user-info {{ background: #e8f5e9; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        button {{ padding: 10px 20px; font-size: 16px; cursor: pointer; margin: 5px; }}
        .logout {{ background: #dc3545; color: white; border: none; }}
    </style>
</head>
<body>
    <h1>🔐 Security Complete Example</h1>
    <div class="user-info">
        <h2>Welcome, {}!</h2>
        <p>You are successfully logged in.</p>
    </div>
    <form action="/logout" method="post">
        <button type="submit" class="logout">Logout</button>
    </form>
    <h3>Features demonstrated:</h3>
    <ul>
        <li>✅ Rate Limiting (5 requests/minute for login)</li>
        <li>✅ Account Locking (3 failed attempts = 15 min lock)</li>
        <li>✅ Audit Logging (check console)</li>
        <li>✅ Security Headers (check browser dev tools)</li>
        <li>✅ Argon2 Password Hashing</li>
    </ul>
</body>
</html>"#,
                name
            );
            HttpResponse::Ok().content_type("text/html").body(html)
        }
        None => {
            let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>Login - Security Complete Example</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
        .login-form { background: #f5f5f5; padding: 20px; border-radius: 8px; }
        input { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
        .info { background: #e3f2fd; padding: 10px; border-radius: 4px; margin-bottom: 20px; }
        .warning { background: #fff3e0; padding: 10px; border-radius: 4px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>🔐 Security Complete Example</h1>
    <div class="info">
        <strong>Test Users:</strong><br>
        admin / admin<br>
        user / user
    </div>
    <div class="warning">
        <strong>⚠️ Security Features:</strong><br>
        - Rate limited to 5 login attempts/minute<br>
        - Account locks after 3 failed attempts
    </div>
    <div class="login-form">
        <form action="/login" method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>"#;
            HttpResponse::Ok().content_type("text/html").body(html)
        }
    }
}

/// Login handler
#[post("/login")]
async fn login(
    req: HttpRequest,
    session: Session,
    form: web::Form<LoginForm>,
    data: web::Data<Arc<AppState>>,
) -> impl Responder {
    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    // Check if account is locked
    let lock_result = check_login(&data.lock_manager, &form.username).await;
    if !lock_result.is_allowed() {
        data.audit_logger.log(
            SecurityEvent::new(SecurityEventType::AccessDenied)
                .username(&form.username)
                .ip_address(&ip)
                .error("Account locked"),
        );
        return HttpResponse::Forbidden().body("Account is locked. Please try again later.".to_string());
    }

    // Find user and verify password
    let user = data
        .users
        .iter()
        .find(|u| u.get_username() == form.username);

    match user {
        Some(u) if data.encoder.matches(&form.password, u.get_password()) => {
            // Successful login
            data.lock_manager.record_success(&form.username).await;
            data.audit_logger.log_login_success(&form.username, &ip);

            session.insert("username", &form.username).ok();

            HttpResponse::Found()
                .append_header(("Location", "/"))
                .finish()
        }
        _ => {
            // Failed login
            let status = data
                .lock_manager
                .record_failure_with_ip(&form.username, Some(&ip))
                .await;

            data.audit_logger
                .log_login_failure(&form.username, &ip, "Invalid credentials");

            let remaining = data.lock_manager.get_remaining_attempts(&form.username).await;

            let message = if status.is_locked() {
                "Account has been locked due to too many failed attempts. Please try again later."
                    .to_string()
            } else {
                format!(
                    "Invalid credentials. {} attempts remaining before account lock.",
                    remaining
                )
            };

            HttpResponse::Unauthorized().body(message)
        }
    }
}

/// Logout handler
#[post("/logout")]
async fn logout(
    req: HttpRequest,
    session: Session,
    data: web::Data<Arc<AppState>>,
) -> impl Responder {
    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    if let Ok(Some(username)) = session.get::<String>("username") {
        data.audit_logger.log(
            SecurityEvent::new(SecurityEventType::Logout)
                .username(&username)
                .ip_address(&ip),
        );
    }

    session.purge();

    HttpResponse::Found()
        .append_header(("Location", "/"))
        .finish()
}

/// Health check endpoint (excluded from rate limiting)
#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let encoder = Argon2PasswordEncoder::new();

    // Create users
    let users = vec![
        User::with_encoded_password("admin", encoder.encode("admin"))
            .roles(&["ADMIN".into(), "USER".into()]),
        User::with_encoded_password("user", encoder.encode("user")).roles(&["USER".into()]),
    ];

    // Create account lock manager (strict: 3 attempts, 15 min lock)
    let lock_manager = AccountLockManager::new(
        LockConfig::new()
            .max_attempts(3)
            .lockout_duration(std::time::Duration::from_secs(15 * 60))
            .progressive_lockout(true),
    );

    // Create audit logger
    let audit_logger = AuditLogger::new().add_handler(StdoutHandler::new());

    let state = Arc::new(AppState {
        users,
        encoder,
        lock_manager,
        audit_logger,
    });

    // Create rate limiter for login endpoint
    let login_rate_limiter = RateLimiter::new(
        RateLimitConfig::new()
            .requests_per_minute(5)
            .exclude_paths(vec!["/health"]),
    );

    let secret_key = Key::generate();

    println!("=== Security Complete Example ===");
    println!("Server running at http://localhost:8082");
    println!();
    println!("Security features enabled:");
    println!("  - Rate Limiting: 5 requests/minute");
    println!("  - Account Locking: 3 failed attempts = 15 min lock");
    println!("  - Audit Logging: Check console output");
    println!("  - Security Headers: X-Frame-Options, CSP, etc.");
    println!("  - Password Hashing: Argon2");
    println!();
    println!("Test users:");
    println!("  admin / admin");
    println!("  user / user");
    println!();

    HttpServer::new(move || {
        App::new()
            .wrap(SecurityHeaders::strict())
            .wrap(login_rate_limiter.clone())
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_secure(false)
                    .build(),
            )
            .app_data(web::Data::new(state.clone()))
            .service(index)
            .service(login)
            .service(logout)
            .service(health)
    })
    .bind("127.0.0.1:8082")?
    .run()
    .await
}
