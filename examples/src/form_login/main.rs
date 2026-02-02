//! Form-based Login Example
//!
//! This example demonstrates form-based login with redirect support,
//! similar to Spring Security's formLogin().
//!
//! # Run
//! ```bash
//! cargo run --example form_login
//! ```
//!
//! # Test
//! Open http://localhost:8080 in a browser.
//! You will be redirected to /login page.
//! Login with admin:admin or user:user.

use actix_security::http::security::{
    Argon2PasswordEncoder, FormLoginConfig, FormLoginHandler, PasswordEncoder,
    SessionAuthenticator, SessionConfig, SessionFixationStrategy, User,
};
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, get, post, web, App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use std::sync::Arc;

/// Login form data
#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    #[serde(default)]
    _remember_me: bool, // TODO: Implement remember-me functionality
}

/// Application state
struct AppState {
    users: Vec<User>,
    encoder: Argon2PasswordEncoder,
    form_login_handler: FormLoginHandler,
    session_config: SessionConfig,
}

/// Home page - requires authentication
#[get("/")]
async fn index(session: Session, data: web::Data<Arc<AppState>>) -> impl Responder {
    match SessionAuthenticator::get_session_user(&session, &data.session_config) {
        Some(user) => {
            let html = format!(
                r#"<!DOCTYPE html>
<html>
<head><title>Home</title></head>
<body>
    <h1>Welcome, {}!</h1>
    <p>Roles: {:?}</p>
    <form action="/logout" method="post">
        <button type="submit">Logout</button>
    </form>
</body>
</html>"#,
                user.get_username(),
                user.get_roles()
            );
            HttpResponse::Ok().content_type("text/html").body(html)
        }
        None => {
            // Redirect to login
            HttpResponse::Found()
                .append_header(("Location", "/login"))
                .finish()
        }
    }
}

/// Login page (GET)
#[get("/login")]
async fn login_page(session: Session, data: web::Data<Arc<AppState>>) -> impl Responder {
    // If already logged in, redirect to home
    if SessionAuthenticator::get_session_user(&session, &data.session_config).is_some() {
        return HttpResponse::Found()
            .append_header(("Location", "/"))
            .finish();
    }

    let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
        form { display: flex; flex-direction: column; gap: 15px; }
        input { padding: 10px; font-size: 16px; }
        button { padding: 10px; font-size: 16px; background: #007bff; color: white; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
        .error { color: red; }
        .info { color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <h1>Login</h1>
    <form action="/login" method="post">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <label>
            <input type="checkbox" name="remember_me" value="true">
            Remember me
        </label>
        <button type="submit">Sign In</button>
    </form>
    <p class="info">Test accounts: admin:admin, user:user</p>
</body>
</html>"#;

    HttpResponse::Ok().content_type("text/html").body(html)
}

/// Login page with error
#[get("/login-error")]
async fn login_error() -> impl Responder {
    let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
        form { display: flex; flex-direction: column; gap: 15px; }
        input { padding: 10px; font-size: 16px; }
        button { padding: 10px; font-size: 16px; background: #007bff; color: white; border: none; cursor: pointer; }
        .error { color: red; background: #ffe6e6; padding: 10px; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>Login</h1>
    <p class="error">Invalid username or password</p>
    <form action="/login" method="post">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Sign In</button>
    </form>
</body>
</html>"#;

    HttpResponse::Ok().content_type("text/html").body(html)
}

/// Login processing (POST)
#[post("/login")]
async fn login_submit(
    session: Session,
    data: web::Data<Arc<AppState>>,
    form: web::Form<LoginForm>,
) -> impl Responder {
    // Find user and verify password
    let user = data
        .users
        .iter()
        .find(|u| u.get_username() == form.username);

    match user {
        Some(user) if data.encoder.matches(&form.password, user.get_password()) => {
            // Use FormLoginHandler for success response
            data.form_login_handler
                .on_authentication_success(&session, user, None)
        }
        _ => {
            // Redirect to login page with error
            data.form_login_handler.on_authentication_failure()
        }
    }
}

/// Logout
#[post("/logout")]
async fn logout(session: Session, data: web::Data<Arc<AppState>>) -> impl Responder {
    SessionAuthenticator::logout(&session, &data.session_config);
    HttpResponse::Found()
        .append_header(("Location", "/login"))
        .finish()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let encoder = Argon2PasswordEncoder::new();

    // Create test users
    let users = vec![
        User::with_encoded_password("admin", encoder.encode("admin"))
            .roles(&["ADMIN".into(), "USER".into()]),
        User::with_encoded_password("user", encoder.encode("user")).roles(&["USER".into()]),
    ];

    // Session configuration
    let session_config = SessionConfig::new()
        .user_key("user")
        .fixation_strategy(SessionFixationStrategy::MigrateSession);

    // Form login configuration (similar to Spring Security's formLogin())
    let form_login_config = FormLoginConfig::new()
        .login_page("/login")
        .login_processing_url("/login")
        .default_success_url("/")
        .failure_url("/login-error")
        .logout_url("/logout")
        .logout_success_url("/login");

    let form_login_handler = FormLoginHandler::new(form_login_config, session_config.clone());

    let state = Arc::new(AppState {
        users,
        encoder,
        form_login_handler,
        session_config,
    });

    let secret_key = Key::generate();

    println!("=== Form Login Example ===");
    println!("Server running at http://localhost:8080");
    println!();
    println!("Open http://localhost:8080 in your browser.");
    println!("Test accounts: admin:admin, user:user");
    println!();

    HttpServer::new(move || {
        App::new()
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_secure(false)
                    .build(),
            )
            .app_data(web::Data::new(state.clone()))
            .service(index)
            .service(login_page)
            .service(login_error)
            .service(login_submit)
            .service(logout)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
