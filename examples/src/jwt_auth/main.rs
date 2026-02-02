//! JWT Authentication Example
//!
//! This example demonstrates JWT-based authentication with Actix Security.
//!
//! # Run
//! ```bash
//! cargo run --example jwt_auth
//! ```
//!
//! # Test
//! ```bash
//! # Get a token
//! TOKEN=$(curl -s -X POST http://localhost:8080/login \
//!   -H "Content-Type: application/json" \
//!   -d '{"username":"admin","password":"admin"}' | jq -r '.access_token')
//!
//! # Use the token
//! curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/me
//!
//! # Get token pair with refresh token
//! curl -X POST http://localhost:8080/login \
//!   -H "Content-Type: application/json" \
//!   -d '{"username":"admin","password":"admin"}'
//! ```

use actix_security::http::security::{
    Argon2PasswordEncoder, JwtAuthenticator, JwtConfig, JwtTokenService, PasswordEncoder, User,
};
use actix_web::{get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Login credentials
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

/// Token response
#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    token_type: String,
    expires_in: u64,
}

/// Application state
struct AppState {
    users: Vec<User>,
    encoder: Argon2PasswordEncoder,
    jwt_service: JwtTokenService,
    jwt_authenticator: JwtAuthenticator,
}

/// Login endpoint - returns JWT token
#[post("/login")]
async fn login(
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
            // Generate token pair
            match data.jwt_service.generate_token_pair(user) {
                Ok(pair) => HttpResponse::Ok().json(TokenResponse {
                    access_token: pair.access_token,
                    refresh_token: pair.refresh_token,
                    token_type: pair.token_type,
                    expires_in: pair.expires_in,
                }),
                Err(e) => HttpResponse::InternalServerError().body(format!("Token error: {}", e)),
            }
        }
        _ => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid credentials"
        })),
    }
}

/// Refresh token endpoint
#[post("/refresh")]
async fn refresh(
    data: web::Data<Arc<AppState>>,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    let refresh_token = match body.get("refresh_token").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "refresh_token required"
            }))
        }
    };

    match data.jwt_service.refresh_tokens(refresh_token) {
        Ok(pair) => HttpResponse::Ok().json(TokenResponse {
            access_token: pair.access_token,
            refresh_token: pair.refresh_token,
            token_type: pair.token_type,
            expires_in: pair.expires_in,
        }),
        Err(e) => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": format!("Invalid refresh token: {}", e)
        })),
    }
}

/// Protected endpoint - requires valid JWT
#[get("/api/me")]
async fn me(req: HttpRequest, data: web::Data<Arc<AppState>>) -> impl Responder {
    // Extract token from Authorization header
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Missing or invalid Authorization header"
            }))
        }
    };

    // Validate token and get user
    match data.jwt_authenticator.validate_token(token) {
        Ok(token_data) => {
            let claims = token_data.claims;
            HttpResponse::Ok().json(serde_json::json!({
                "username": claims.sub,
                "roles": claims.roles,
                "authorities": claims.authorities,
                "expires_at": claims.exp
            }))
        }
        Err(e) => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": format!("Invalid token: {}", e)
        })),
    }
}

/// Public endpoint
#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "JWT Authentication Example",
        "endpoints": {
            "POST /login": "Get JWT token (body: {username, password})",
            "POST /refresh": "Refresh token (body: {refresh_token})",
            "GET /api/me": "Get current user (requires Authorization header)"
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
            .roles(&["ADMIN".into(), "USER".into()])
            .authorities(&["users:read".into(), "users:write".into()]),
        User::with_encoded_password("user", encoder.encode("user"))
            .roles(&["USER".into()])
            .authorities(&["users:read".into()]),
    ];

    // JWT configuration
    let jwt_config = JwtConfig::new("my-super-secret-key-for-jwt-signing")
        .issuer("actix-security-example")
        .audience("api-users")
        .expiration_secs(3600); // 1 hour

    let jwt_service = JwtTokenService::new(jwt_config.clone()).refresh_expiration_days(7); // 7 days

    let jwt_authenticator = JwtAuthenticator::new(jwt_config);

    let state = Arc::new(AppState {
        users,
        encoder,
        jwt_service,
        jwt_authenticator,
    });

    println!("=== JWT Authentication Example ===");
    println!("Server running at http://localhost:8080");
    println!();
    println!("Test users: admin:admin, user:user");
    println!();
    println!("Try:");
    println!("  # Get token");
    println!("  curl -X POST http://localhost:8080/login \\");
    println!("    -H 'Content-Type: application/json' \\");
    println!("    -d '{{\"username\":\"admin\",\"password\":\"admin\"}}'");
    println!();
    println!("  # Use token");
    println!("  curl -H 'Authorization: Bearer <token>' http://localhost:8080/api/me");
    println!();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .service(index)
            .service(login)
            .service(refresh)
            .service(me)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
