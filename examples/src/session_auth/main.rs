//! Session-based Authentication Example
//!
//! This example demonstrates session-based authentication with session fixation protection.
//!
//! # Run
//! ```bash
//! cargo run --example session_auth
//! ```
//!
//! # Test
//! ```bash
//! # Login (stores session cookie)
//! curl -c cookies.txt -X POST http://localhost:8080/login \
//!   -H "Content-Type: application/json" \
//!   -d '{"username":"admin","password":"admin"}'
//!
//! # Access protected route with session
//! curl -b cookies.txt http://localhost:8080/dashboard
//!
//! # Logout
//! curl -b cookies.txt -c cookies.txt -X POST http://localhost:8080/logout
//! ```

use actix_security::http::security::{
    Argon2PasswordEncoder, PasswordEncoder, SessionAuthenticator, SessionConfig,
    SessionFixationStrategy, User,
};
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, get, post, web, App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use std::sync::Arc;

/// Login credentials
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

/// Application state
struct AppState {
    users: Vec<User>,
    encoder: Argon2PasswordEncoder,
    session_config: SessionConfig,
}

/// Login endpoint
#[post("/login")]
async fn login(
    session: Session,
    data: web::Data<Arc<AppState>>,
    credentials: web::Json<LoginRequest>,
) -> impl Responder {
    // Find user and verify password
    let user = data
        .users
        .iter()
        .find(|u| u.get_username() == credentials.username);

    match user {
        Some(user)
            if data
                .encoder
                .matches(&credentials.password, user.get_password()) =>
        {
            // Login with session fixation protection
            match SessionAuthenticator::login(&session, user, &data.session_config) {
                Ok(()) => HttpResponse::Ok().json(serde_json::json!({
                    "message": "Login successful",
                    "username": user.get_username(),
                    "roles": user.get_roles()
                })),
                Err(e) => HttpResponse::InternalServerError().body(format!("Session error: {}", e)),
            }
        }
        _ => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid credentials"
        })),
    }
}

/// Logout endpoint
#[post("/logout")]
async fn logout(session: Session, data: web::Data<Arc<AppState>>) -> impl Responder {
    SessionAuthenticator::logout(&session, &data.session_config);
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Logged out successfully"
    }))
}

/// Protected dashboard
#[get("/dashboard")]
async fn dashboard(session: Session, data: web::Data<Arc<AppState>>) -> impl Responder {
    // Check if user is authenticated via session
    match SessionAuthenticator::get_session_user(&session, &data.session_config) {
        Some(user) => HttpResponse::Ok().json(serde_json::json!({
            "message": format!("Welcome to dashboard, {}!", user.get_username()),
            "user": {
                "username": user.get_username(),
                "roles": user.get_roles(),
                "authorities": user.get_authorities()
            }
        })),
        None => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Not authenticated",
            "hint": "Please login first at POST /login"
        })),
    }
}

/// Public home page
#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Session Authentication Example",
        "endpoints": {
            "POST /login": "Login with credentials",
            "POST /logout": "Logout and clear session",
            "GET /dashboard": "Protected dashboard (requires session)"
        }
    }))
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

    // Session configuration with fixation protection
    let session_config = SessionConfig::new()
        .user_key("user") // Key to store user in session
        .fixation_strategy(SessionFixationStrategy::MigrateSession); // Protect against session fixation

    let state = Arc::new(AppState {
        users,
        encoder,
        session_config,
    });

    // Generate a random key for session encryption
    let secret_key = Key::generate();

    println!("=== Session Authentication Example ===");
    println!("Server running at http://localhost:8080");
    println!();
    println!("Session features:");
    println!("  - Session fixation protection (MigrateSession)");
    println!("  - 30-minute session timeout");
    println!("  - Secure cookie-based sessions");
    println!();
    println!("Test users: admin:admin, user:user");
    println!();
    println!("Try:");
    println!("  # Login");
    println!("  curl -c cookies.txt -X POST http://localhost:8080/login \\");
    println!("    -H 'Content-Type: application/json' \\");
    println!("    -d '{{\"username\":\"admin\",\"password\":\"admin\"}}'");
    println!();
    println!("  # Access dashboard");
    println!("  curl -b cookies.txt http://localhost:8080/dashboard");
    println!();

    HttpServer::new(move || {
        App::new()
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_secure(false) // Set to true in production with HTTPS
                    .build(),
            )
            .app_data(web::Data::new(state.clone()))
            .service(index)
            .service(login)
            .service(logout)
            .service(dashboard)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
